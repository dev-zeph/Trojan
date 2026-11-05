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
// Returns empty string if not installed. On Windows it also checks the ".exe"
// form so callers can pass the bare name (e.g. "nuclei").
func ManagedBinaryPath(name string) string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	base := filepath.Join(home, ".trojan", "bin", name)
	for _, p := range []string{base, base + exeSuffix()} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// exeSuffix is ".exe" on Windows, empty elsewhere — appended to managed
// scanner-binary filenames so Windows executables are named/found correctly.
func exeSuffix() string {
	if runtime.GOOS == "windows" {
		return ".exe"
	}
	return ""
}

// spaceReserveMB is left free on the user's disk after any install, so
// installing scanners can never fill the disk and disrupt other apps.
const spaceReserveMB = 500

// ensureSpace refuses an install that would leave less than spaceReserveMB
// free. If free space can't be read, the install goes ahead.
func ensureSpace(dir string, needMB int) error {
	// Measure the nearest folder that exists (the target may not yet).
	for {
		if _, err := os.Stat(dir); err == nil || filepath.Dir(dir) == dir {
			break
		}
		dir = filepath.Dir(dir)
	}
	free, ok := freeMB(dir)
	if !ok {
		return nil
	}
	if free < int64(needMB)+spaceReserveMB {
		return fmt.Errorf("not enough disk space: %d MB free, need about %d MB plus %d MB headroom", free, needMB, spaceReserveMB)
	}
	return nil
}

// installLog records install problems in ~/.trojan/logs/install.log for
// troubleshooting. They are not printed: a scanner that can't install is
// skipped quietly and the scan runs with the rest, and the next scan tries
// again.
func installLog(format string, args ...any) {
	dir, err := trojanDir()
	if err != nil {
		return
	}
	logs := filepath.Join(dir, "logs")
	if os.MkdirAll(logs, 0o700) != nil {
		return
	}
	f, err := os.OpenFile(filepath.Join(logs, "install.log"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer f.Close()
	fmt.Fprintf(f, "%s %s\n", time.Now().Format(time.RFC3339), fmt.Sprintf(format, args...))
}

// clearQuarantine removes the macOS quarantine extended attribute from a downloaded binary
// so Gatekeeper does not block execution. No-op on non-macOS systems.
func clearQuarantine(path string) {
	if runtime.GOOS == "darwin" {
		exec.Command("/usr/bin/xattr", "-d", "com.apple.quarantine", path).Run() //nolint:errcheck // absent attribute is fine
	}
}

// scannerMissing reports whether a scanner needs installing: its binary is
// absent, or (for pip scanners) its environment is broken or incomplete.
func scannerMissing(s ScannerManifest, asset PlatformAsset, dest string) bool {
	if _, err := os.Stat(dest); err != nil {
		return true
	}
	if asset.Archive == ArchivePip {
		name, _, _ := strings.Cut(asset.PipPackage, "=")
		return !pipScannerHealthy(name)
	}
	return false
}

// EnsureScanners installs any missing scanners: pinned versions only, each
// checked against its checksum. A scanner that can't be installed (offline,
// low disk) is logged and skipped; scans run with the scanners that are
// available, and the next run tries again.
func EnsureScanners() error {
	return ensureList(Scanners)
}

// EnsureDastScanners installs any missing DAST scanners (e.g. Nuclei).
// Called lazily by `trojan dast` on first run rather than by `trojan init`.
func EnsureDastScanners() error {
	return ensureList(DastScanners)
}

func ensureList(list []ScannerManifest) error {
	binDir, err := TrojanBinDir()
	if err != nil {
		return err
	}
	platform := runtime.GOOS + "/" + runtime.GOARCH

	type job struct {
		s     ScannerManifest
		asset PlatformAsset
		dest  string
	}
	var jobs []job
	for _, s := range list {
		asset, ok := s.Platforms[platform]
		if !ok {
			continue // not offered on this platform
		}
		dest := filepath.Join(binDir, s.Binary+exeSuffix())
		if scannerMissing(s, asset, dest) {
			jobs = append(jobs, job{s, asset, dest})
		}
	}
	if len(jobs) == 0 {
		return nil
	}

	fmt.Println("Setting up Trojan's scanners (first run only)...")
	for _, j := range jobs {
		var err error
		if j.asset.Archive == ArchivePip {
			err = installPip(j.s, j.asset, binDir)
		} else {
			err = installBinary(j.s, j.asset, j.dest)
		}
		if err != nil {
			installLog("%s %s: %v", j.s.Name, j.s.Version, err)
			continue
		}
		color.Green("  ✓ %s\n", j.s.Name)
	}
	fmt.Println()
	return nil
}

// installBinary downloads a pinned, checksummed scanner (retrying once) and
// moves it into place only once it is complete.
func installBinary(s ScannerManifest, asset PlatformAsset, dest string) error {
	if err := ensureSpace(filepath.Dir(dest), s.InstallMB); err != nil {
		return err
	}
	err := downloadScanner(asset, dest)
	if err != nil {
		err = downloadScanner(asset, dest)
	}
	if err == nil {
		clearQuarantine(dest)
	}
	return err
}

// fetchVerified downloads an asset to a temp file and checks it against its
// pinned checksum. An asset without a checksum is refused. The caller removes
// the returned file.
func fetchVerified(asset PlatformAsset) (string, error) {
	if asset.SHA256 == "" {
		return "", fmt.Errorf("no checksum configured for %s, so it was not installed", asset.URL)
	}
	tmp, err := os.CreateTemp("", "trojan-download-*")
	if err != nil {
		return "", fmt.Errorf("could not create temp file: %w", err)
	}
	tmpPath := tmp.Name()
	fail := func(err error) (string, error) {
		tmp.Close()
		os.Remove(tmpPath)
		return "", err
	}

	client := &http.Client{Timeout: 10 * time.Minute}
	resp, err := client.Get(asset.URL)
	if err != nil {
		return fail(fmt.Errorf("download failed: %w", err))
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fail(fmt.Errorf("download failed: HTTP %d", resp.StatusCode))
	}
	if _, err := io.Copy(tmp, resp.Body); err != nil {
		return fail(fmt.Errorf("download failed: %w", err))
	}
	if err := tmp.Close(); err != nil {
		return fail(err)
	}
	actual, err := sha256File(tmpPath)
	if err != nil {
		os.Remove(tmpPath)
		return "", fmt.Errorf("checksum failed: %w", err)
	}
	if actual != asset.SHA256 {
		os.Remove(tmpPath)
		return "", fmt.Errorf("checksum mismatch\n    expected: %s\n    got:      %s\n    The downloaded file may be corrupted or tampered with.", asset.SHA256, actual)
	}
	return tmpPath, nil
}

// downloadScanner downloads, verifies, and installs a single scanner binary.
// The binary is written beside dest and renamed into place only when it is
// complete, so an interrupted install (e.g. a full disk) never leaves a
// broken binary that would later be mistaken for an installed scanner.
func downloadScanner(asset PlatformAsset, dest string) error {
	archive, err := fetchVerified(asset)
	if err != nil {
		return err
	}
	defer os.Remove(archive)

	partial := dest + ".partial"
	os.Remove(partial)
	defer os.Remove(partial)

	switch asset.Archive {
	case ArchiveDirect:
		err = installDirect(archive, partial)
	case ArchiveTarGz:
		err = extractTarGz(archive, asset.BinaryInArchive, partial)
	case ArchiveZip:
		err = extractZip(archive, asset.BinaryInArchive, partial)
	default:
		err = fmt.Errorf("unknown archive type: %s", asset.Archive)
	}
	if err != nil {
		return err
	}
	if err := os.Chmod(partial, 0o755); err != nil {
		return err
	}
	return os.Rename(partial, dest)
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

// HasSpace reports whether installing or downloading about needMB into dir
// would still leave the safety headroom free. Unknown free space counts as
// enough.
func HasSpace(dir string, needMB int) bool {
	return ensureSpace(dir, needMB) == nil
}
