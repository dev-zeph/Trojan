package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/dev-zeph/trojan/internal/memory"
	"github.com/dev-zeph/trojan/internal/normalizer"
)

func hiddenScan(root string) *normalizer.ScanResult {
	return &normalizer.ScanResult{
		ProjectPath: root,
		Findings: []normalizer.Finding{
			{ID: "a", Scanner: "bearer", RuleID: "hardcoded_secret", FilePath: "src/LoginForm.tsx", LineNumber: 6,
				Title: "Usage of hard-coded secret", Severity: normalizer.SeverityCritical, Status: normalizer.StatusOpen,
				Verdict: "likely_fp", VerdictReason: "A field label, not a password.", VerdictConfidence: 0.9},
			{ID: "b", Scanner: "bearer", RuleID: "sql_injection", FilePath: "src/db.ts", LineNumber: 3,
				Title: "SQL injection", Severity: normalizer.SeverityHigh, Status: normalizer.StatusOpen},
		},
	}
}

func latest(t *testing.T, s *Server) scanResponse {
	t.Helper()
	rec := httptest.NewRecorder()
	s.handleLatestScan(rec, httptest.NewRequest(http.MethodGet, "/api/scans/latest", nil))
	var resp scanResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	return resp
}

func post(t *testing.T, s *Server, path string) int {
	t.Helper()
	rec := httptest.NewRecorder()
	s.handleFindingAction(rec, httptest.NewRequest(http.MethodPost, path, nil))
	return rec.Code
}

func TestMarkRealRecordsMemoryAndSurvivesReopen(t *testing.T) {
	root := t.TempDir()
	s := New(hiddenScan(root), nil)

	if code := post(t, s, "/api/findings/a/real"); code != http.StatusOK {
		t.Fatalf("status %d", code)
	}
	if f := latest(t, s).Findings[0]; f.Verdict != "confirmed" || f.HiddenAsFalseAlarm() {
		t.Fatalf("finding should be shown now: %+v", f)
	}

	store, err := memory.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	evs, _ := store.UserConfirmed()
	store.Close()
	if len(evs) != 1 || evs[0].RuleID != "hardcoded_secret" || evs[0].File != "src/LoginForm.tsx" {
		t.Fatalf("memory: %+v", evs)
	}

	// A report reopened from the old scan file (still likely_fp) honors it.
	reopened := New(hiddenScan(root), nil)
	if f := latest(t, reopened).Findings[0]; f.Verdict != "confirmed" {
		t.Fatalf("reopened report ignored the decision: %+v", f)
	}
}

func TestMarkFalseAlarmHidesFinding(t *testing.T) {
	root := t.TempDir()
	s := New(hiddenScan(root), nil)
	if code := post(t, s, "/api/findings/b/false-alarm"); code != http.StatusOK {
		t.Fatalf("status %d", code)
	}
	if f := latest(t, s).Findings[1]; !f.HiddenAsFalseAlarm() || f.VerdictReason == "" {
		t.Fatalf("finding should be hidden with a reason: %+v", f)
	}
	if code := post(t, s, "/api/findings/zzz/real"); code != http.StatusNotFound {
		t.Fatalf("unknown id: %d", code)
	}
}

func TestLatestScanWithoutMemoryCreatesNothing(t *testing.T) {
	root := t.TempDir()
	scan := hiddenScan(root)
	scan.TriageNote = "Trojan couldn't double-check every finding for false alarms."
	resp := latest(t, New(scan, nil))
	if resp.TriageNote == "" || resp.Findings[0].Verdict != "likely_fp" {
		t.Fatalf("resp %+v", resp)
	}
	if _, err := os.Stat(filepath.Join(root, ".trojan")); !os.IsNotExist(err) {
		t.Fatal("reading a report must not create .trojan")
	}
}
