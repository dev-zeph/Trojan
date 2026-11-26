package mcpserver

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dev-zeph/trojan/internal/normalizer"
)

func TestResolveAgainstRootParentRelative(t *testing.T) {
	parent := t.TempDir()
	proj := filepath.Join(parent, "leaky-app")
	if err := os.MkdirAll(filepath.Join(proj, "src"), 0o755); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(proj, "src", "config.ts")
	if err := os.WriteFile(target, []byte("export {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	stored := filepath.Join("leaky-app", "src", "config.ts")
	abs, ok := normalizer.ResolveAgainstRoot(proj, stored)
	if !ok {
		t.Fatalf("should resolve parent-relative path %q under %s", stored, proj)
	}
	if abs != target && filepath.Clean(abs) != filepath.Clean(target) {
		t.Fatalf("resolved %q, want %q", abs, target)
	}
	if rel := normalizer.RelToProject(proj, stored); rel != "src/config.ts" {
		t.Fatalf("RelToProject = %q", rel)
	}
}

func TestVerifyOnceMissingFileIsNotFound(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	proj := filepath.Join(home, "app")
	if err := os.MkdirAll(proj, 0o755); err != nil {
		t.Fatal(err)
	}
	_, err := normalizer.SaveScanResult(proj, []normalizer.Finding{{
		ID: "gitleaks-2", Scanner: "gitleaks", RuleID: "stripe-access-token",
		Title: "Stripe", FilePath: "src/missing.ts", LineNumber: 1,
		CodeSnippet: "x", Status: normalizer.StatusOpen,
	}})
	if err != nil {
		t.Fatal(err)
	}
	res, err := VerifyOnce(proj, "gitleaks-2")
	if err != nil {
		t.Fatal(err)
	}
	if res.Fixed || !res.NotFound {
		t.Fatalf("missing file must be NOT FOUND, not fixed: %+v", res)
	}
}

func TestVerifyOnceParentRelativePathIsFound(t *testing.T) {
	// Simulate scan-once run from a parent folder: the stored path includes
	// the project directory prefix, but the scan root is the project itself.
	home := t.TempDir()
	t.Setenv("HOME", home)
	parent := filepath.Join(home, "ws")
	proj := filepath.Join(parent, "leaky-app")
	if err := os.MkdirAll(filepath.Join(proj, "src"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(proj, "src", "config.ts"), []byte("const x = 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Write the scan file as if paths were not yet normalized (scan-once
	// from the parent folder). Finding JSON uses exported field names.
	scanDir := filepath.Join(proj, ".trojan", "scans")
	if err := os.MkdirAll(scanDir, 0o755); err != nil {
		t.Fatal(err)
	}
	doc := normalizer.ScanResult{
		ProjectPath: proj,
		Findings: []normalizer.Finding{{
			ID: "gitleaks-2", Scanner: "gitleaks", RuleID: "stripe-access-token",
			Title: "Stripe", FilePath: "leaky-app/src/config.ts", LineNumber: 1,
			CodeSnippet: "x", Status: normalizer.StatusOpen,
		}},
	}
	raw, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(scanDir, "2026-11-26T12-00-00.json"), raw, 0o644); err != nil {
		t.Fatal(err)
	}
	abs, ok := normalizer.ResolveAgainstRoot(proj, "leaky-app/src/config.ts")
	if !ok || !strings.HasSuffix(filepath.ToSlash(abs), "leaky-app/src/config.ts") {
		t.Fatalf("expected parent-relative path to resolve, ok=%v abs=%q", ok, abs)
	}
	res, err := VerifyOnce(proj, "gitleaks-2")
	if err != nil {
		t.Fatal(err)
	}
	if res.NotFound {
		t.Fatalf("file exists under the scan root; should not be NOT FOUND: %+v", res)
	}
	// The file was not changed, so if gitleaks runs it may or may not still
	// report the rule (the snippet is not a real secret). The important
	// assertion is that we did not treat a resolvable path as missing, and
	// therefore did not skip the scanner and claim a fix by default.
}

func TestScanSummary(t *testing.T) {
	res := &normalizer.ScanResult{
		Findings: []normalizer.Finding{
			{Severity: normalizer.SeverityCritical},
			{Severity: normalizer.SeverityCritical},
			{Severity: normalizer.SeverityCritical},
			{Severity: normalizer.SeverityHigh},
			{Severity: normalizer.SeverityHigh},
			{Severity: normalizer.SeverityHigh},
			{Severity: normalizer.SeverityHigh},
			{Severity: normalizer.SeverityHigh},
			{Severity: normalizer.SeverityHigh},
		},
	}
	got := ScanSummary(res, "/tmp/fixture/leaky-app/.trojan/scans/2026-11-26T08-37-31.json")
	want := "Scan done: 9 findings (3 critical, 6 high). Saved to .trojan/scans/2026-11-26T08-37-31.json. Ask your AI editor to run get_findings."
	if got != want {
		t.Fatalf("\n got: %s\nwant: %s", got, want)
	}
}
