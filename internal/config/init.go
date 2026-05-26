package config

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"

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

// EnsureScanners checks which scanners are missing and installs pinned versions.
func EnsureScanners() error {
	binDir, err := TrojanBinDir()
	if err != nil {
		return err
	}

	platform := runtime.GOOS + "/" + runtime.GOARCH // e.g. "darwin/arm64"

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

		fmt.Printf("  Installing %s v%s... ", s.Name, s.Version)

		if asset.Archive == ArchivePip {
			if err := installViaPip(asset.PipPackage, binDir); err != nil {
				color.Red("failed\n")
				fmt.Printf("    Error: %v\n", err)
				continue
			}
		} else {
			dest := filepath.Join(binDir, s.Binary)
			if err := downloadScanner(asset, dest); err != nil {
				color.Red("failed\n")
				fmt.Printf("    Error: %v\n", err)
				continue
			}
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


// RunInit is the full init flow — called by `trojan init`.
func RunInit(projectPath string) error {
	fmt.Println("Setting up Trojan...\n")

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
