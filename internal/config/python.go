package config

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// Trojan's own Python, used only to run the pip-based scanners (Semgrep, and
// Checkov on Apple Silicon). A new Mac has no working Python until Apple's
// developer tools are installed, and calling the /usr/bin/python3 stub pops up
// Apple's install dialog, so Trojan never depends on the system Python. This is
// a pinned, checksummed python-build-standalone build unpacked into
// ~/.trojan/python; it touches nothing else on the machine.

const managedPythonVersion = "3.12.15"

var managedPython = map[string]PlatformAsset{
	"darwin/arm64": {
		URL:    "https://github.com/astral-sh/python-build-standalone/releases/download/20261013/cpython-3.12.15%2B20261013-aarch64-apple-darwin-install_only.tar.gz",
		SHA256: "ba32036ad8f4c434d97a1ee7feef8b7edc0fac16777639b97e39c74a108e4440",
	},
	"darwin/amd64": {
		URL:    "https://github.com/astral-sh/python-build-standalone/releases/download/20261013/cpython-3.12.15%2B20261013-x86_64-apple-darwin-install_only.tar.gz",
		SHA256: "9686ddd8639b855905447ea4a16eb54a804a9ef12afbe7c9ecb1412d9c1fbc98",
	},
	"linux/amd64": {
		URL:    "https://github.com/astral-sh/python-build-standalone/releases/download/20261013/cpython-3.12.15%2B20261013-x86_64-unknown-linux-gnu-install_only.tar.gz",
		SHA256: "5d546fc004fc2435fa142eb8f42ed8de5eb4725963dc22f7e6671014a80eb560",
	},
	"linux/arm64": {
		URL:    "https://github.com/astral-sh/python-build-standalone/releases/download/20261013/cpython-3.12.15%2B20261013-aarch64-unknown-linux-gnu-install_only.tar.gz",
		SHA256: "34a43010cc05982d8b5debbad7d09f7b1200117ebf018f7acfd656895e408205",
	},
	"windows/amd64": {
		URL:    "https://github.com/astral-sh/python-build-standalone/releases/download/20261013/cpython-3.12.15%2B20261013-x86_64-pc-windows-msvc-install_only.tar.gz",
		SHA256: "bbc902d4d187ac4914915bf538196a064b49109a33a104965b5164ced5b80a1e",
	},
}

// managedPythonMB is roughly what the unpacked Python takes on disk.
const managedPythonMB = 120

func trojanDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".trojan"), nil
}

// managedPythonPath is where Trojan's Python interpreter lives once installed.
func managedPythonPath() string {
	dir, err := trojanDir()
	if err != nil {
		return ""
	}
	if runtime.GOOS == "windows" {
		return filepath.Join(dir, "python", "python.exe")
	}
	return filepath.Join(dir, "python", "bin", "python3")
}

func runs(exe string, args ...string) bool {
	if exe == "" {
		return false
	}
	return exec.Command(exe, args...).Run() == nil
}

// ensureManagedPython returns Trojan's Python, downloading it on first use.
func ensureManagedPython() (string, error) {
	exe := managedPythonPath()
	if runs(exe, "--version") {
		return exe, nil
	}
	platform := runtime.GOOS + "/" + runtime.GOARCH
	asset, ok := managedPython[platform]
	if !ok {
		return "", fmt.Errorf("no managed Python for %s", platform)
	}
	dir, err := trojanDir()
	if err != nil {
		return "", err
	}
	if err := ensureSpace(dir, managedPythonMB); err != nil {
		return "", err
	}
	archive, err := fetchVerified(asset)
	if err != nil {
		return "", err
	}
	defer os.Remove(archive)

	// Unpack next to the final location, then swap it in, so an interrupted
	// unpack (e.g. a full disk) never leaves a half-installed Python behind.
	tmp, err := os.MkdirTemp(dir, "python-partial-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(tmp)
	if err := extractTree(archive, tmp, "python/"); err != nil {
		return "", fmt.Errorf("unpacking Python: %w", err)
	}
	final := filepath.Join(dir, "python")
	os.RemoveAll(final)
	if err := os.Rename(tmp, final); err != nil {
		return "", err
	}
	if !runs(exe, "--version") {
		return "", fmt.Errorf("managed Python %s did not start", managedPythonVersion)
	}
	return exe, nil
}

// extractTree unpacks a .tar.gz into dest, keeping only entries under prefix
// (with prefix stripped). Entries that would land outside dest are refused.
func extractTree(archivePath, dest, prefix string) error {
	f, err := os.Open(archivePath)
	if err != nil {
		return err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer gz.Close()

	root, err := filepath.Abs(dest)
	if err != nil {
		return err
	}
	inside := func(p string) bool {
		return p == root || strings.HasPrefix(p, root+string(filepath.Separator))
	}

	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		name := strings.TrimPrefix(filepath.ToSlash(hdr.Name), "./")
		if !strings.HasPrefix(name, prefix) {
			continue
		}
		name = strings.TrimPrefix(name, prefix)
		if name == "" {
			continue
		}
		target := filepath.Join(root, filepath.FromSlash(name))
		if !inside(target) {
			return fmt.Errorf("archive entry %q escapes the install folder", hdr.Name)
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			out, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.FileMode(hdr.Mode)&0o777|0o600)
			if err != nil {
				return err
			}
			_, cerr := io.Copy(out, tr)
			if err := out.Close(); cerr == nil {
				cerr = err
			}
			if cerr != nil {
				return cerr
			}
		case tar.TypeSymlink:
			link := filepath.Join(filepath.Dir(target), filepath.FromSlash(hdr.Linkname))
			if filepath.IsAbs(hdr.Linkname) || !inside(link) {
				return fmt.Errorf("archive link %q escapes the install folder", hdr.Name)
			}
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			os.Remove(target)
			if err := os.Symlink(hdr.Linkname, target); err != nil {
				return err
			}
		}
	}
}

// venvDir keeps each pip scanner in its own environment so their
// dependencies can't conflict. Semgrep keeps the original "venv" name.
func venvDir(pkg string) (string, error) {
	dir, err := trojanDir()
	if err != nil {
		return "", err
	}
	if pkg == "semgrep" {
		return filepath.Join(dir, "venv"), nil
	}
	return filepath.Join(dir, "venv-"+pkg), nil
}

func venvBinDir(venv string) string {
	if runtime.GOOS == "windows" {
		return filepath.Join(venv, "Scripts")
	}
	return filepath.Join(venv, "bin")
}

// okMarker is written into a venv only after its package installed fully, so
// an interrupted pip install is redone instead of trusted.
func okMarker(venv, pipPackage string) string {
	return filepath.Join(venv, ".trojan-ok-"+strings.ReplaceAll(pipPackage, "=", "_"))
}

// pipScannerHealthy reports whether a pip scanner's environment is complete
// and its Python still starts (a venv breaks if the Python it was built from
// is removed, which is common for venvs made from a system or Homebrew Python).
func pipScannerHealthy(pkg string) bool {
	venv, err := venvDir(pkg)
	if err != nil {
		return false
	}
	py := filepath.Join(venvBinDir(venv), "python"+exeSuffix())
	if !runs(py, "-c", "") {
		return false
	}
	matches, _ := filepath.Glob(filepath.Join(venv, ".trojan-ok-"+pkg+"_*"))
	if len(matches) > 0 {
		return true
	}
	// Venvs from before the marker existed: trust them if the tool is there.
	_, err = os.Stat(filepath.Join(venvBinDir(venv), pkg+exeSuffix()))
	return err == nil
}

// installPip installs a pinned pip package into its own venv built from
// Trojan's Python and links the tool into ~/.trojan/bin.
func installPip(s ScannerManifest, asset PlatformAsset, binDir string) error {
	py, err := ensureManagedPython()
	if err != nil {
		return err
	}
	name, _, _ := strings.Cut(asset.PipPackage, "=")
	venv, err := venvDir(name)
	if err != nil {
		return err
	}
	if err := ensureSpace(filepath.Dir(venv), s.InstallMB); err != nil {
		return err
	}
	// Always rebuild from Trojan's Python: an existing venv may be broken or
	// made from a Python too old for the pinned version.
	os.RemoveAll(venv)
	if out, err := exec.Command(py, "-m", "venv", venv).CombinedOutput(); err != nil {
		return fmt.Errorf("creating venv: %w: %s", err, out)
	}
	pip := filepath.Join(venvBinDir(venv), "pip"+exeSuffix())
	var lastErr error
	for _, pkg := range []string{asset.PipPackage, s.PipFallback} {
		if pkg == "" {
			continue
		}
		out, err := exec.Command(pip, "install", "--quiet", "--disable-pip-version-check", "--no-input", pkg).CombinedOutput()
		if err != nil {
			lastErr = fmt.Errorf("pip install %s: %w: %s", pkg, err, out)
			continue
		}
		os.WriteFile(okMarker(venv, pkg), nil, 0o644) //nolint:errcheck // a missing marker only means a reinstall later
		return linkTool(filepath.Join(venvBinDir(venv), name+exeSuffix()), filepath.Join(binDir, s.Binary+exeSuffix()))
	}
	os.RemoveAll(venv)
	return lastErr
}

// linkTool points ~/.trojan/bin/<tool> at the venv's tool. Windows symlinks
// need elevated rights, so the executable is copied there instead.
func linkTool(src, dest string) error {
	tmp := dest + ".partial"
	os.Remove(tmp)
	var err error
	if runtime.GOOS == "windows" {
		err = installDirect(src, tmp)
	} else {
		err = os.Symlink(src, tmp)
	}
	if err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, dest)
}
