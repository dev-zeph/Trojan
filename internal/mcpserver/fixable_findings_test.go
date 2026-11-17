package mcpserver

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dev-zeph/trojan/internal/normalizer"
	"github.com/mark3labs/mcp-go/mcp"
)

// TestGetFixableFindings_PrioritisesAndCaps builds a scan far larger than the
// MCP response budget and checks that get_fixable_findings excludes likely_fp,
// prefers confirmed then needs_manual, caps the number returned, and reports how
// many were omitted — instead of dumping all findings and overflowing.
func TestGetFixableFindings_PrioritisesAndCaps(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	proj := t.TempDir()

	big := strings.Repeat("const x = compute(req.query.v);\n", 60) // ~1.9KB each
	var findings []normalizer.Finding
	add := func(id, verdict string, sev normalizer.Severity) {
		findings = append(findings, normalizer.Finding{
			ID: id, Title: "Issue " + id, Severity: sev, Scanner: "semgrep",
			Category: "sast", FilePath: "app.js", LineNumber: 3, Status: normalizer.StatusOpen,
			Verdict: verdict, SurroundingCode: big,
		})
	}
	// Interleaved so correct output depends on sorting, not input order.
	fpIDs := map[string]bool{}
	for i := 0; i < 8; i++ {
		add("conf-"+itoa(i), "confirmed", normalizer.SeverityHigh)
		add("manual-"+itoa(i), "needs_manual", normalizer.SeverityMedium)
		add("none-"+itoa(i), "", normalizer.SeverityLow)
		if i < 5 {
			id := "fp-" + itoa(i)
			add(id, normalizer.VerdictLikelyFP, normalizer.SeverityCritical)
			fpIDs[id] = true
		}
	}
	add("manual-8", "needs_manual", normalizer.SeverityMedium)
	add("manual-9", "needs_manual", normalizer.SeverityMedium)
	// 8 confirmed + 10 needs_manual + 8 none + 5 likely_fp = 31; fixable = 26.

	scan := normalizer.ScanResult{Timestamp: time.Now(), ProjectPath: proj, Findings: findings}
	data, _ := json.Marshal(scan)
	scanPath := filepath.Join(proj, ".trojan", "scans", "2026-11-04T10-00-00.json")
	if err := os.MkdirAll(filepath.Dir(scanPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(scanPath, data, 0o644); err != nil {
		t.Fatal(err)
	}

	pf := func(context.Context, mcp.CallToolRequest) (string, error) { return proj, nil }
	out, isErr := callTool(t, handleGetFixableFindings(pf), nil)
	if isErr {
		t.Fatalf("handler error: %s", out)
	}
	if len(out) > 55000 {
		t.Errorf("response is %d bytes — too large for the MCP budget", len(out))
	}

	var got struct {
		Total    int `json:"total"`
		Returned int `json:"returned"`
		Omitted  int `json:"omitted"`
		Note     string
		Findings []struct {
			ID      string `json:"id"`
			Verdict string `json:"verdict"`
		} `json:"findings"`
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("bad JSON: %v\n%s", err, out)
	}

	if got.Total != 26 {
		t.Errorf("total fixable = %d, want 26 (likely_fp excluded)", got.Total)
	}
	if got.Returned != 15 || len(got.Findings) != 15 {
		t.Errorf("returned = %d / %d, want 15 (capped)", got.Returned, len(got.Findings))
	}
	if got.Omitted != got.Total-got.Returned || got.Omitted <= 0 {
		t.Errorf("omitted = %d, want %d", got.Omitted, got.Total-got.Returned)
	}
	if got.Note == "" {
		t.Error("expected a note about the omitted findings")
	}

	confirmed, seenLower := 0, false
	for i, f := range got.Findings {
		if fpIDs[f.ID] || f.Verdict == normalizer.VerdictLikelyFP {
			t.Errorf("likely_fp finding %q must not be returned", f.ID)
		}
		switch f.Verdict {
		case "confirmed":
			if seenLower {
				t.Errorf("confirmed finding %q appears after a lower-priority one (index %d)", f.ID, i)
			}
			confirmed++
		default:
			seenLower = true
		}
	}
	if confirmed != 8 {
		t.Errorf("all 8 confirmed findings should be surfaced first; got %d", confirmed)
	}
}

func itoa(i int) string { return string(rune('0' + i)) }
