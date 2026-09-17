package scanners

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// runScript runs a temporary shell script (unix) or batch file (windows) and
// returns its stdout plus the *exec.Cmd error, mirroring exactly what
// cmd.Output() gives Trivy.Run() for a real trivy invocation — including a
// populated *exec.ExitError.Stderr on non-zero exit. This lets us exercise
// parseTrivyOutput's error-handling contract against a real OS process
// without depending on the actual trivy binary being installed.
func runScript(t *testing.T, body string) ([]byte, error) {
	t.Helper()

	dir := t.TempDir()
	var scriptPath string
	var cmd *exec.Cmd

	if runtime.GOOS == "windows" {
		scriptPath = filepath.Join(dir, "fake.bat")
		if err := os.WriteFile(scriptPath, []byte(body), 0755); err != nil {
			t.Fatalf("failed to write fake script: %v", err)
		}
		cmd = exec.Command("cmd", "/C", scriptPath)
	} else {
		scriptPath = filepath.Join(dir, "fake.sh")
		if err := os.WriteFile(scriptPath, []byte("#!/bin/sh\n"+body), 0755); err != nil {
			t.Fatalf("failed to write fake script: %v", err)
		}
		cmd = exec.Command(scriptPath)
	}

	output, err := cmd.Output()
	return output, err
}

func TestParseTrivyOutput_ExitOneWithValidJSON(t *testing.T) {
	// --exit-code 1 means "vulnerabilities found" — trivy still writes a
	// full JSON report to stdout and exits 1. This must parse normally, not
	// be treated as a failure.
	json := `{"SchemaVersion":2,"Results":[{"Target":"go.sum","Type":"gomod","Vulnerabilities":[{"VulnerabilityID":"CVE-2024-1234","PkgName":"example","InstalledVersion":"1.0.0","Severity":"HIGH"}]}]}`
	output, err := runScript(t, "cat <<'EOF'\n"+json+"\nEOF\nexit 1\n")
	if err == nil {
		t.Fatalf("expected the script to exit non-zero, got nil error")
	}

	result, perr := parseTrivyOutput(output, err)
	if perr != nil {
		t.Fatalf("expected exit code 1 with valid JSON to parse cleanly, got error: %v", perr)
	}
	if len(result.Results) != 1 || len(result.Results[0].Vulnerabilities) != 1 {
		t.Fatalf("expected one result with one vulnerability, got: %+v", result)
	}
	if result.Results[0].Vulnerabilities[0].VulnerabilityID != "CVE-2024-1234" {
		t.Fatalf("unexpected vulnerability ID: %+v", result.Results[0].Vulnerabilities[0])
	}
}

func TestParseTrivyOutput_FatalErrorPropagatesStderr(t *testing.T) {
	// A fatal error (e.g. the docker-credential-helper failure this bug is
	// about) exits non-zero with a code other than 1, empty stdout, and a
	// real diagnostic on stderr. The returned error must surface that
	// stderr, not a generic/parse error.
	stderrMsg := `FATAL run error: init error: DB error: failed to download vulnerability DB: error getting credentials - err: exec: "docker-credential-desktop" executable file not found in $PATH`
	output, err := runScript(t, "echo '"+stderrMsg+"' 1>&2\nexit 2\n")
	if err == nil {
		t.Fatalf("expected the script to exit non-zero, got nil error")
	}

	_, perr := parseTrivyOutput(output, err)
	if perr == nil {
		t.Fatalf("expected a fatal exit to produce an error, got nil")
	}
	if !strings.Contains(perr.Error(), "docker-credential-desktop") {
		t.Fatalf("expected the real stderr cause to be in the error, got: %v", perr)
	}
	if strings.Contains(perr.Error(), "unexpected end of JSON input") {
		t.Fatalf("error should name the real cause, not a JSON parse failure, got: %v", perr)
	}
}

func TestParseTrivyOutput_EmptyStdoutIsDiagnosedNotMisparsed(t *testing.T) {
	// Even if something upstream ever calls this with a nil run error but
	// empty output (e.g. a scanner that silently produced nothing), the
	// empty-stdout guard should fire with a clear message instead of falling
	// through to json.Unmarshal and returning "unexpected end of JSON input".
	_, perr := parseTrivyOutput([]byte(""), nil)
	if perr == nil {
		t.Fatalf("expected empty stdout to produce a diagnostic error, got nil")
	}
	if strings.Contains(perr.Error(), "unexpected end of JSON input") {
		t.Fatalf("expected a clear diagnostic, not a raw JSON parse error, got: %v", perr)
	}
	if !strings.Contains(perr.Error(), "no output") {
		t.Fatalf("expected the error to mention the empty-output cause, got: %v", perr)
	}
}

func TestParseTrivyOutput_CleanSuccess(t *testing.T) {
	// Exit 0 (no vulnerabilities found) with a minimal valid JSON report.
	output, err := runScript(t, `echo '{"SchemaVersion":2,"Results":[]}'`)
	if err != nil {
		t.Fatalf("expected clean exit, got error: %v", err)
	}

	result, perr := parseTrivyOutput(output, err)
	if perr != nil {
		t.Fatalf("expected clean output to parse without error, got: %v", perr)
	}
	if len(result.Results) != 0 {
		t.Fatalf("expected no results, got: %+v", result.Results)
	}
}

func TestParseTrivyOutput_NonExitCodeOneFailureWithoutStderr(t *testing.T) {
	// A failure that produces no stderr at all should still surface the
	// underlying *exec.ExitError rather than silently returning success.
	output, err := runScript(t, "exit 2\n")
	if err == nil {
		t.Fatalf("expected the script to exit non-zero, got nil error")
	}

	_, perr := parseTrivyOutput(output, err)
	if perr == nil {
		t.Fatalf("expected a non-zero, non-exit-code-1 failure to produce an error, got nil")
	}
	if !strings.Contains(perr.Error(), "trivy failed") {
		t.Fatalf("expected the error to be identifiable as a trivy failure, got: %v", perr)
	}
}
