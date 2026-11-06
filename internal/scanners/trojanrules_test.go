package scanners

import (
	"os/exec"
	"testing"
)

// TestTrojanSemgrepRules runs `semgrep --test` over Trojan's own rules and
// their annotated test files. A rule that fails to parse makes semgrep reject
// the whole config, which would drop every SAST finding from a scan, so this
// guards the scan as well as the individual rules. Skipped without semgrep.
func TestTrojanSemgrepRules(t *testing.T) {
	bin, err := exec.LookPath("semgrep")
	if err != nil {
		t.Skip("semgrep not installed")
	}
	out, err := exec.Command(bin, "--test", "--metrics=off", "semgreprules").CombinedOutput()
	if err != nil {
		t.Fatalf("semgrep --test failed: %v\n%s", err, out)
	}
}

func TestMergeGitleaksResults(t *testing.T) {
	files := []gitleaksResult{{RuleID: "stripe-access-token", Secret: "sk_test_a", File: "server.js"}}
	history := []gitleaksResult{
		{RuleID: "stripe-access-token", Secret: "sk_test_a", File: "server.js", Commit: "abc"},
		{RuleID: "aws-access-token", Secret: "AKIA1", File: "old.env", Commit: "def"},
		{RuleID: "aws-access-token", Secret: "AKIA1", File: "old.env", Commit: "0ff"},
	}
	got := mergeGitleaksResults(files, history)
	if len(got) != 2 {
		t.Fatalf("want 2 results (current secret once, history-only secret once), got %d: %+v", len(got), got)
	}
	if got[0].Commit != "" {
		t.Errorf("secret still in the files should keep its file location, got commit %q", got[0].Commit)
	}
	if got[1].Secret != "AKIA1" {
		t.Errorf("history-only secret missing: %+v", got[1])
	}
}

func TestIsLocalEnvFile(t *testing.T) {
	cases := map[string]bool{
		"/app/.env":                  true,
		"/app/.env.local":            true,
		"/app/.env.production":       true,
		"/app/.env.example":          false,
		"/app/.env.local.example":    false,
		"/app/.env.sample":           false,
		"/app/server.js":             false,
		"/app/config/environment.ts": false,
	}
	for path, want := range cases {
		if got := isLocalEnvFile(path); got != want {
			t.Errorf("isLocalEnvFile(%q) = %v, want %v", path, got, want)
		}
	}
}

func TestDedupeGitleaksResults(t *testing.T) {
	in := []gitleaksResult{
		{File: "public/a.html", StartLine: 204, RuleID: "generic-api-key", Secret: "x"},
		{File: "public/a.html", StartLine: 204, RuleID: "generic-api-key", Secret: "y"},
		{File: "public/a.html", StartLine: 205, RuleID: "generic-api-key", Secret: "z"},
	}
	if got := dedupeGitleaksResults(in); len(got) != 2 {
		t.Fatalf("want 2 after dedupe, got %d", len(got))
	}
}

// Secrets scanning and Trojan's rules must run on projects without .git (a
// folder never committed): gating on .git used to skip Gitleaks entirely.
func TestRelevantScannersAlwaysIncludesSecretsAndSAST(t *testing.T) {
	all := []Scanner{Semgrep{}, Gitleaks{}}
	got := RelevantScanners(all, ProjectType{HasNode: true, HasGitHistory: false})
	names := map[string]bool{}
	for _, s := range got {
		names[s.Name()] = true
	}
	for _, want := range []string{"semgrep", "gitleaks"} {
		if !names[want] {
			t.Errorf("%s not run for a project without .git", want)
		}
	}
}
