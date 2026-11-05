package mcpserver

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dev-zeph/trojan/internal/normalizer"
)

// stubScanners puts a fake binary for every managed scanner in a temp HOME so
// nothing is downloaded; semgrep exits 2 (a crash, not "findings found").
func stubScanners(t *testing.T) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("PATH", "/usr/bin:/bin")
	bin := filepath.Join(home, ".trojan", "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"trivy", "gitleaks", "checkov", "syft", "bearer", "nuclei"} {
		os.WriteFile(filepath.Join(bin, name), []byte("#!/bin/sh\nexit 0\n"), 0o755) //nolint:errcheck
	}
	os.WriteFile(filepath.Join(bin, "semgrep"), []byte("#!/bin/sh\necho 'could not download rules' >&2\nexit 2\n"), 0o755) //nolint:errcheck
	// pip scanners (semgrep; checkov on Apple Silicon) are checked for a
	// working venv: give each a fake one so nothing is downloaded.
	for _, venv := range []string{"venv", "venv-checkov"} {
		vb := filepath.Join(home, ".trojan", venv, "bin")
		os.MkdirAll(vb, 0o755)                                                                                                  //nolint:errcheck
		os.WriteFile(filepath.Join(vb, "python"), []byte("#!/bin/sh\nexit 0\n"), 0o755)                                         //nolint:errcheck
		os.WriteFile(filepath.Join(home, ".trojan", venv, ".trojan-ok-"+strings.TrimPrefix(venv, "venv-")+"_stub"), nil, 0o644) //nolint:errcheck
	}
	os.WriteFile(filepath.Join(home, ".trojan", "venv", ".trojan-ok-semgrep_stub"), nil, 0o644) //nolint:errcheck
}

// A scanner that fails to run returns no findings; verify_fix must not read
// that as "fixed".
func TestVerifyOnceScannerFailureIsNotFixed(t *testing.T) {
	stubScanners(t)
	proj := t.TempDir()
	os.WriteFile(filepath.Join(proj, "app.py"), []byte("import pickle\n"), 0o644) //nolint:errcheck
	f := normalizer.Finding{ID: "semgrep-0", Scanner: "semgrep", RuleID: "python.pickle", FilePath: "app.py", LineNumber: 1, Severity: normalizer.SeverityHigh, Title: "pickle"}
	if _, err := normalizer.SaveScanResult(proj, []normalizer.Finding{f}); err != nil {
		t.Fatal(err)
	}

	res, err := VerifyOnce(proj, "semgrep-0")
	if err == nil {
		t.Fatalf("expected an error when semgrep fails, got %+v", res)
	}
	if !strings.Contains(err.Error(), "couldn't confirm") {
		t.Errorf("error should say the fix couldn't be confirmed: %v", err)
	}
}
