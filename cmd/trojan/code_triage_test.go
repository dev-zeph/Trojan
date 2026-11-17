package main

import (
	"errors"
	"testing"

	"github.com/dev-zeph/trojan/internal/ai"
	"github.com/dev-zeph/trojan/internal/normalizer"
)

func TestTriageCodeFindings_FailureKeepsEverythingAndNotes(t *testing.T) {
	orig := codeTriage
	t.Cleanup(func() { codeTriage = orig })
	codeTriage = func(fs []normalizer.Finding, _ ai.CodeTriageOptions) (ai.CodeTriageStats, error) {
		return ai.CodeTriageStats{Total: len(fs), Checked: len(fs)}, errors.New("triage failed (status 402)")
	}
	fs := []normalizer.Finding{{ID: "a", Severity: normalizer.SeverityHigh}, {ID: "b", Severity: normalizer.SeverityLow}}
	note := triageCodeFindings(t.TempDir(), fs, "tok")
	if note == "" || len(fs) != 2 {
		t.Fatalf("note %q, findings %d", note, len(fs))
	}
	if c := visibleSeverityCounts(fs); c["high"] != 1 || c["low"] != 1 {
		t.Fatalf("all findings should count: %v", c)
	}
}

func TestTriageCodeFindings_SignedOutSkips(t *testing.T) {
	orig := codeTriage
	t.Cleanup(func() { codeTriage = orig })
	called := false
	codeTriage = func([]normalizer.Finding, ai.CodeTriageOptions) (ai.CodeTriageStats, error) {
		called = true
		return ai.CodeTriageStats{}, nil
	}
	if note := triageCodeFindings(t.TempDir(), []normalizer.Finding{{ID: "a"}}, ""); note != "" || called {
		t.Fatal("no token: no AI check")
	}
}

func TestVisibleSeverityCountsSkipsHidden(t *testing.T) {
	fs := []normalizer.Finding{
		{Severity: normalizer.SeverityCritical, Verdict: "likely_fp"},
		{Severity: normalizer.SeverityCritical, Verdict: "confirmed"},
		{Severity: normalizer.SeverityHigh, Verdict: "needs_manual"},
	}
	if c := visibleSeverityCounts(fs); c["critical"] != 1 || c["high"] != 1 {
		t.Fatalf("counts %v", c)
	}
}
