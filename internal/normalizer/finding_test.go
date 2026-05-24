package normalizer

import (
	"testing"
)

func TestFindingSeverityValues(t *testing.T) {
	tests := []struct {
		severity Severity
		expected string
	}{
		{SeverityCritical, "critical"},
		{SeverityHigh, "high"},
		{SeverityMedium, "medium"},
		{SeverityLow, "low"},
		{SeverityInfo, "info"},
	}

	for _, tt := range tests {
		if string(tt.severity) != tt.expected {
			t.Errorf("expected severity %q, got %q", tt.expected, tt.severity)
		}
	}
}

func TestFindingStatusValues(t *testing.T) {
	tests := []struct {
		status   Status
		expected string
	}{
		{StatusOpen, "open"},
		{StatusResolved, "resolved"},
		{StatusSuppressed, "suppressed"},
	}

	for _, tt := range tests {
		if string(tt.status) != tt.expected {
			t.Errorf("expected status %q, got %q", tt.expected, tt.status)
		}
	}
}

func TestFindingStruct(t *testing.T) {
	f := Finding{
		ID:          "semgrep-0",
		Scanner:     "semgrep",
		Category:    "sast",
		Severity:    SeverityMedium,
		Title:       "SQL Injection",
		RawMessage:  "Possible SQL injection at line 42",
		FilePath:    "main.go",
		LineNumber:  42,
		CodeSnippet: `db.Query("SELECT * FROM users WHERE id = " + id)`,
		RuleID:      "go.lang.security.sql-injection",
		Status:      StatusOpen,
	}

	if f.Scanner != "semgrep" {
		t.Errorf("expected scanner 'semgrep', got %q", f.Scanner)
	}
	if f.Severity != SeverityMedium {
		t.Errorf("expected severity 'medium', got %q", f.Severity)
	}
	if f.Status != StatusOpen {
		t.Errorf("expected status 'open', got %q", f.Status)
	}
	if f.LineNumber != 42 {
		t.Errorf("expected line number 42, got %d", f.LineNumber)
	}
}
