package mcpserver

import (
	"encoding/json"
	"testing"

	"github.com/dev-zeph/trojan/internal/memory"
	"github.com/dev-zeph/trojan/internal/normalizer"
)

// get_findings lists AI likely false alarms (with the reason) instead of
// hiding them, and mark_real flips one to confirmed and remembers it.
func TestGetFindingsShowsVerdictsAndMarkReal(t *testing.T) {
	project, root := brainFixture(t, "vibeapp")
	if _, err := normalizer.SaveScanResult(root, []normalizer.Finding{
		{ID: "lbl", Severity: normalizer.SeverityCritical, Title: "Hard-coded secret", RuleID: "js.secret", FilePath: "app/login.tsx", LineNumber: 4,
			Status: normalizer.StatusOpen, Verdict: "likely_fp", VerdictReason: "A form label, not a password.", VerdictConfidence: 0.9},
		{ID: "real", Severity: normalizer.SeverityHigh, Title: "SQLi", RuleID: "js.sqli", FilePath: "app/api/export/route.ts", LineNumber: 5,
			Status: normalizer.StatusOpen, Verdict: "confirmed", VerdictReason: "User input reaches the query."},
	}); err != nil {
		t.Fatal(err)
	}

	var out struct {
		LikelyFalseAlarms int `json:"likely_false_alarms"`
		Findings          []struct {
			ID            string `json:"id"`
			Verdict       string `json:"verdict"`
			VerdictReason string `json:"verdict_reason"`
		}
	}
	if err := json.Unmarshal([]byte(mustCall(t, handleGetFindings(project), nil)), &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Findings) != 2 || out.LikelyFalseAlarms != 1 {
		t.Fatalf("likely false alarms must be listed, not hidden: %+v", out)
	}
	for _, f := range out.Findings {
		if f.VerdictReason == "" {
			t.Fatalf("missing verdict_reason: %+v", f)
		}
	}

	mustCall(t, handleMarkReal(project), map[string]any{"id": "lbl"})
	scan, err := loadLatestScan(root)
	if err != nil {
		t.Fatal(err)
	}
	if scan.Findings[0].Verdict != "confirmed" {
		t.Fatalf("scan not updated: %+v", scan.Findings[0])
	}
	store, err := memory.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if evs, _ := store.UserConfirmed(); len(evs) != 1 || evs[0].RuleID != "js.secret" {
		t.Fatalf("memory: %+v", evs)
	}
	if _, isErr := callTool(t, handleMarkReal(project), map[string]any{"id": "nope"}); !isErr {
		t.Fatal("unknown id should error")
	}
}
