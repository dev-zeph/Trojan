package config

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/fatih/color"
)

// TrojanBinDir returns ~/.trojan/bin, creating it if needed.
func TrojanBinDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("could not find home directory: %w", err)
	}
	dir := filepath.Join(home, ".trojan", "bin")
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", fmt.Errorf("could not create %s: %w", dir, err)
	}
	return dir, nil
}

// ManagedBinaryPath returns the path to a scanner binary managed by Trojan.
// Returns empty string if not installed.
func ManagedBinaryPath(name string) string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	p := filepath.Join(home, ".trojan", "bin", name)
	if _, err := os.Stat(p); err == nil {
		return p
	}
	return ""
}

// resolveLatestVersion queries the GitHub releases API for the latest version of a scanner.
// Returns the raw version string (tag with prefix stripped).
func resolveLatestVersion(repo, tagPrefix string) (string, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	url := fmt.Sprintf("https://api.github.com/repos/%s/releases/latest", repo)
	resp, err := client.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GitHub API returned %d", resp.StatusCode)
	}
	var release struct {
		TagName string `json:"tag_name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return "", err
	}
	return strings.TrimPrefix(release.TagName, tagPrefix), nil
}

// downloadWithRetry attempts to download a scanner binary, retrying once on failure.
func downloadWithRetry(asset PlatformAsset, dest string) error {
	err := downloadScanner(asset, dest)
	if err == nil {
		clearQuarantine(dest)
		return nil
	}
	// Retry once
	fmt.Print("retrying... ")
	err = downloadScanner(asset, dest)
	if err == nil {
		clearQuarantine(dest)
	}
	return err
}

// clearQuarantine removes the macOS quarantine extended attribute from a downloaded binary
// so Gatekeeper does not block execution. No-op on non-macOS systems.
func clearQuarantine(path string) {
	if runtime.GOOS == "darwin" {
		exec.Command("xattr", "-d", "com.apple.quarantine", path).Run()
	}
}

// tryInstallLatest attempts to download the latest GitHub release of a scanner.
// Returns true if installation succeeded.
func tryInstallLatest(s ScannerManifest, pinnedAsset PlatformAsset, dest string) bool {
	latestVersion, err := resolveLatestVersion(s.GitHubRepo, s.TagPrefix)
	if err != nil || latestVersion == s.Version {
		return false
	}

	latestURL := strings.ReplaceAll(pinnedAsset.URL, s.Version, latestVersion)
	latestAsset := PlatformAsset{
		URL:             latestURL,
		SHA256:          "", // cannot verify checksum for dynamically resolved versions
		Archive:         pinnedAsset.Archive,
		BinaryInArchive: pinnedAsset.BinaryInArchive,
	}

	fmt.Printf("  Installing %s v%s (latest)... ", s.Name, latestVersion)
	if err := downloadWithRetry(latestAsset, dest); err != nil {
		color.Yellow("failed\n")
		return false
	}
	color.Green("done\n")
	return true
}

// installPipDefensive installs a pip-based scanner with multiple fallback strategies:
//  1. Try latest version via pip (if python3 is available)
//  2. Fall back to pinned version via pip
//  3. Fall back to Homebrew (if available)
func installPipDefensive(s ScannerManifest, asset PlatformAsset, binDir string) error {
	name := strings.SplitN(asset.PipPackage, "==", 2)[0]

	hasPython := exec.Command("python3", "--version").Run() == nil

	if hasPython {
		// Try latest version first
		if s.GitHubRepo != "" {
			if latestVersion, err := resolveLatestVersion(s.GitHubRepo, s.TagPrefix); err == nil && latestVersion != s.Version {
				latestPkg := name + "==" + latestVersion
				if err := installViaPip(latestPkg, binDir); err == nil {
					return nil
				}
			}
		}
		// Fall back to pinned version
		if err := installViaPip(asset.PipPackage, binDir); err == nil {
			return nil
		}
	}

	// Fallback: try Homebrew
	if _, err := exec.LookPath("brew"); err == nil {
		fmt.Print("(trying brew) ")
		if err := runCaptured("brew", "install", "--quiet", name); err == nil {
			if p, err := exec.LookPath(name); err == nil {
				dest := filepath.Join(binDir, name)
				os.Remove(dest)
				return os.Symlink(p, dest)
			}
		}
	}

	if !hasPython {
		return fmt.Errorf("python3 not found — install with: xcode-select --install")
	}
	return fmt.Errorf("pip install failed — try manually: pip3 install %s", asset.PipPackage)
}

// EnsureScanners checks which scanners are missing and installs them.
// For each missing scanner it tries the latest GitHub release first, then
// falls back to the pinned version. Downloads are retried once on failure.
func EnsureScanners() error {
	binDir, err := TrojanBinDir()
	if err != nil {
		return err
	}

	platform := runtime.GOOS + "/" + runtime.GOARCH

	missing := []ScannerManifest{}
	for _, s := range Scanners {
		dest := filepath.Join(binDir, s.Binary)
		if _, err := os.Stat(dest); os.IsNotExist(err) {
			missing = append(missing, s)
		}
	}

	if len(missing) == 0 {
		return nil
	}

	fmt.Printf("Installing %d missing scanner(s) to ~/.trojan/bin/...\n\n", len(missing))

	for _, s := range missing {
		asset, ok := s.Platforms[platform]
		if !ok {
			color.Yellow("  %-12s skipped (unsupported platform: %s)\n", s.Name, platform)
			continue
		}

		dest := filepath.Join(binDir, s.Binary)

		// ── pip-based scanners (e.g. Semgrep) ─────────────────────
		if asset.Archive == ArchivePip {
			fmt.Printf("  Installing %s... ", s.Name)
			if err := installPipDefensive(s, asset, binDir); err != nil {
				color.Red("failed\n")
				fmt.Printf("    Error: %v\n", err)
			} else {
				color.Green("done\n")
			}
			continue
		}

		// ── binary scanners ───────────────────────────────────────
		// Try latest version from GitHub first
		if s.GitHubRepo != "" {
			if tryInstallLatest(s, asset, dest) {
				continue
			}
		}

		// Fall back to pinned version with retry
		fmt.Printf("  Installing %s v%s... ", s.Name, s.Version)
		if err := downloadWithRetry(asset, dest); err != nil {
			color.Red("failed\n")
			fmt.Printf("    Error: %v\n", err)
			continue
		}
		color.Green("done\n")
	}

	fmt.Println()
	return nil
}

// installViaPip installs a pinned pip package into ~/.trojan/venv/ and symlinks
// the binary into ~/.trojan/bin/.
func installViaPip(pipPackage, binDir string) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	venvDir := filepath.Join(home, ".trojan", "venv")

	// Create venv if it doesn't exist
	if _, err := os.Stat(venvDir); os.IsNotExist(err) {
		if err := runCaptured("python3", "-m", "venv", venvDir); err != nil {
			return fmt.Errorf("could not create venv (is python3 installed?): %w", err)
		}
	}

	pipBin := filepath.Join(venvDir, "bin", "pip")
	if err := runCaptured(pipBin, "install", "--quiet", "--disable-pip-version-check", pipPackage); err != nil {
		return fmt.Errorf("pip install failed: %w", err)
	}

	// Symlink venv binary into ~/.trojan/bin/
	name := pipPackage
	if idx := len(pipPackage); idx > 0 {
		for i, c := range pipPackage {
			if c == '=' {
				name = pipPackage[:i]
				break
			}
		}
	}
	venvBin := filepath.Join(venvDir, "bin", name)
	dest := filepath.Join(binDir, name)
	os.Remove(dest) // remove stale symlink if present
	return os.Symlink(venvBin, dest)
}

func runCaptured(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w\n%s", err, string(out))
	}
	return nil
}

// downloadScanner downloads, verifies, and installs a single scanner binary.
func downloadScanner(asset PlatformAsset, dest string) error {
	// Download to a temp file
	tmp, err := os.CreateTemp("", "trojan-scanner-*")
	if err != nil {
		return fmt.Errorf("could not create temp file: %w", err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)

	resp, err := http.Get(asset.URL)
	if err != nil {
		return fmt.Errorf("download failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download failed: HTTP %d", resp.StatusCode)
	}

	if _, err := io.Copy(tmp, resp.Body); err != nil {
		tmp.Close()
		return fmt.Errorf("download failed: %w", err)
	}
	tmp.Close()

	// Verify SHA256 if set
	if asset.SHA256 != "" {
		actual, err := sha256File(tmpPath)
		if err != nil {
			return fmt.Errorf("checksum failed: %w", err)
		}
		if actual != asset.SHA256 {
			return fmt.Errorf("checksum mismatch\n    expected: %s\n    got:      %s\n    The downloaded file may be corrupted or tampered with.", asset.SHA256, actual)
		}
	} else {
		color.Yellow("(unverified — no checksum configured) ")
	}

	// Extract or move binary into place
	switch asset.Archive {
	case ArchiveDirect:
		if err := installDirect(tmpPath, dest); err != nil {
			return err
		}
	case ArchiveTarGz:
		if err := extractTarGz(tmpPath, asset.BinaryInArchive, dest); err != nil {
			return err
		}
	case ArchiveZip:
		if err := extractZip(tmpPath, asset.BinaryInArchive, dest); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unknown archive type: %s", asset.Archive)
	}

	return os.Chmod(dest, 0755)
}

func installDirect(src, dest string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.OpenFile(dest, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, in)
	return err
}

func extractTarGz(archivePath, binaryName, dest string) error {
	f, err := os.Open(archivePath)
	if err != nil {
		return err
	}
	defer f.Close()

	gz, err := gzip.NewReader(f)
	if err != nil {
		return fmt.Errorf("not a valid gzip file: %w", err)
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		if filepath.Base(hdr.Name) == binaryName {
			out, err := os.OpenFile(dest, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
			if err != nil {
				return err
			}
			_, copyErr := io.Copy(out, tr)
			out.Close()
			return copyErr
		}
	}
	return fmt.Errorf("binary %q not found inside archive", binaryName)
}

func extractZip(archivePath, binaryName, dest string) error {
	r, err := zip.OpenReader(archivePath)
	if err != nil {
		return fmt.Errorf("not a valid zip file: %w", err)
	}
	defer r.Close()

	for _, f := range r.File {
		if f.Name == binaryName || filepath.Base(f.Name) == filepath.Base(binaryName) {
			rc, err := f.Open()
			if err != nil {
				return err
			}
			out, err := os.OpenFile(dest, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
			if err != nil {
				rc.Close()
				return err
			}
			_, copyErr := io.Copy(out, rc)
			rc.Close()
			out.Close()
			return copyErr
		}
	}
	return fmt.Errorf("binary %q not found inside zip", binaryName)
}


// EnsureDastScanners installs any missing DAST scanners (e.g. Nuclei).
// Called lazily by `trojan dast` on first run rather than by `trojan init`.
// Uses the same latest-first + retry strategy as EnsureScanners.
func EnsureDastScanners() error {
	binDir, err := TrojanBinDir()
	if err != nil {
		return err
	}

	platform := runtime.GOOS + "/" + runtime.GOARCH

	missing := []ScannerManifest{}
	for _, s := range DastScanners {
		dest := filepath.Join(binDir, s.Binary)
		if _, err := os.Stat(dest); os.IsNotExist(err) {
			missing = append(missing, s)
		}
	}

	if len(missing) == 0 {
		return nil
	}

	fmt.Printf("Installing %d DAST scanner(s) to ~/.trojan/bin/...\n\n", len(missing))

	for _, s := range missing {
		asset, ok := s.Platforms[platform]
		if !ok {
			color.Yellow("  %-12s skipped (unsupported platform: %s)\n", s.Name, platform)
			continue
		}

		dest := filepath.Join(binDir, s.Binary)

		// Try latest version from GitHub first
		if s.GitHubRepo != "" {
			if tryInstallLatest(s, asset, dest) {
				continue
			}
		}

		// Fall back to pinned version with retry
		fmt.Printf("  Installing %s v%s... ", s.Name, s.Version)
		if err := downloadWithRetry(asset, dest); err != nil {
			color.Red("failed\n")
			fmt.Printf("    Error: %v\n", err)
			continue
		}
		color.Green("done\n")
	}

	fmt.Println()
	return nil
}

// RunInit is the full init flow — called by `trojan init`.
func RunInit(projectPath string) error {
	PrintLogo()
	fmt.Println("Setting up Trojan...")
	fmt.Println()

	if err := EnsureScanners(); err != nil {
		return err
	}

	if err := ensureGitignore(projectPath); err != nil {
		color.Yellow("Warning: could not update .gitignore: %s\n", err)
	}

	color.Green("Trojan is ready. Run `trojan scan` to scan your project.\n")
	return nil
}

func ensureGitignore(projectPath string) error {
	gitignorePath := projectPath + "/.gitignore"
	entry := "\n# Trojan scan results\n.trojan/\n"

	f, err := os.OpenFile(gitignorePath, os.O_APPEND|os.O_CREATE|os.O_RDWR, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	content, _ := os.ReadFile(gitignorePath)
	if contains(string(content), ".trojan/") {
		return nil
	}

	_, err = f.WriteString(entry)
	return err
}

// Platform returns the current OS for informational purposes.
func Platform() string {
	return runtime.GOOS
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsStr(s, substr))
}

func containsStr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
