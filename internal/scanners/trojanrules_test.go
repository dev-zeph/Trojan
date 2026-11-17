package scanners

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dev-zeph/trojan/internal/normalizer"
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

// secretTitle must read cleanly from the rule id — never the old garbled
// "Leaked Found a Stripe Access Token ..." built from Gitleaks' Description.
func TestSecretTitle(t *testing.T) {
	cases := map[string]string{
		"stripe-access-token": "Hardcoded secret: Stripe Access Token",
		"aws-access-token":    "Hardcoded secret: AWS Access Token",
		"github-pat":          "Hardcoded secret: GitHub PAT",
		"generic-api-key":     "Hardcoded secret: Generic API Key",
		"private-key":         "Hardcoded secret: Private Key",
		"":                    "Hardcoded secret found in code",
	}
	for ruleID, want := range cases {
		if got := secretTitle(gitleaksResult{RuleID: ruleID, Description: "Found a Stripe Access Token, posing a risk"}); got != want {
			t.Errorf("secretTitle(%q) = %q, want %q", ruleID, got, want)
		}
	}
}

func TestSecretSeverity(t *testing.T) {
	cases := []struct {
		r    gitleaksResult
		want normalizer.Severity
	}{
		{gitleaksResult{RuleID: "stripe-access-token", Secret: "sk_live_abc"}, normalizer.SeverityCritical},
		{gitleaksResult{RuleID: "stripe-access-token", Secret: "sk_test_abc"}, normalizer.SeverityHigh},
		{gitleaksResult{RuleID: "aws-access-token", Secret: "AKIAX"}, normalizer.SeverityCritical},
		{gitleaksResult{RuleID: "generic-api-key", Secret: "abc123"}, normalizer.SeverityHigh},
	}
	for _, c := range cases {
		if got := secretSeverity(c.r); got != c.want {
			t.Errorf("secretSeverity(%s %s) = %s, want %s", c.r.RuleID, c.r.Secret, got, c.want)
		}
	}
}

func TestSemgrepFindingSeverity(t *testing.T) {
	var trojanCrit, registryCrit, plainError semgrepResult
	trojanCrit.Extra.Severity = "ERROR"
	trojanCrit.Extra.Metadata.TrojanSeverity = "critical"
	registryCrit.Extra.Severity = "ERROR"
	registryCrit.Extra.Metadata.Impact = "HIGH"
	registryCrit.Extra.Metadata.Likelihood = "HIGH"
	plainError.Extra.Severity = "ERROR"
	plainError.Extra.Metadata.Impact = "HIGH"
	plainError.Extra.Metadata.Likelihood = "LOW"
	if got := semgrepFindingSeverity(trojanCrit); got != normalizer.SeverityCritical {
		t.Errorf("trojan-severity critical: got %s", got)
	}
	if got := semgrepFindingSeverity(registryCrit); got != normalizer.SeverityCritical {
		t.Errorf("registry HIGH/HIGH ERROR: got %s", got)
	}
	if got := semgrepFindingSeverity(plainError); got != normalizer.SeverityHigh {
		t.Errorf("registry HIGH/LOW ERROR: got %s", got)
	}
}

// semgrepSnippet reads the matched line(s) from the file, not semgrep's
// unreliable extra.lines. The reported range must win over a bogus fallback.
func TestSemgrepSnippet(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mw.js")
	src := "line one\n" +
		"  if (req.path.startsWith(\"/admin\")) {\n" +
		"    return res.status(403).send(\"requires login\");\n" +
		"  }\n"
	if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	// Semgrep reported the admin check on line 2 but its extra.lines carried the
	// nested error string. The snippet must follow the reported line.
	got := semgrepSnippet(path, 2, 2, "requires login")
	if got != `if (req.path.startsWith("/admin")) {` {
		t.Errorf("snippet = %q, want the admin-check line", got)
	}
	// Fallback only when the file can't be read.
	if got := semgrepSnippet(filepath.Join(dir, "missing.js"), 2, 2, "fallback text"); got != "fallback text" {
		t.Errorf("missing file snippet = %q, want fallback", got)
	}
}

// End-to-end: the case-sensitive-path-check rule must not report "requires
// login" as the snippet — the snippet comes from the matched admin-check line.
// Skipped without semgrep.
func TestCaseSensitivePathSnippetNotErrorString(t *testing.T) {
	if _, err := exec.LookPath("semgrep"); err != nil {
		t.Skip("semgrep not installed")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "target.js")
	src := "const express = require(\"express\");\n" +
		"const app = express();\n" +
		"app.use((req, res, next) => {\n" +
		"  if (req.path.startsWith(\"/admin\")) {\n" +
		"    if (!req.user || req.user.role !== \"admin\") {\n" +
		"      return res.status(403).send(\"requires login\");\n" +
		"    }\n" +
		"  }\n" +
		"  next();\n" +
		"});\n"
	if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	findings, err := Semgrep{}.Run(dir)
	if err != nil {
		t.Fatal(err)
	}
	var hit *normalizer.Finding
	for i := range findings {
		if strings.Contains(findings[i].RuleID, "case-sensitive-path-check") {
			hit = &findings[i]
			break
		}
	}
	if hit == nil {
		t.Fatalf("rule did not fire; findings = %+v", findings)
	}
	if strings.TrimSpace(hit.CodeSnippet) == "requires login" {
		t.Errorf("snippet is the error string, not the admin check: %q", hit.CodeSnippet)
	}
	if !strings.Contains(hit.CodeSnippet, "req.path") {
		t.Errorf("snippet %q should contain the matched admin check (req.path...)", hit.CodeSnippet)
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
