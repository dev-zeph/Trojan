package ai

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestTriageWireAgreedScanners verifies the corroboration signal (A2) is carried
// on the triage payload: present when multiple scanners agreed, omitted otherwise.
func TestTriageWireAgreedScanners(t *testing.T) {
	corroborated := triageFindingWire{
		ID:             "bearer-0",
		Title:          "SQL Injection",
		Severity:       "high",
		AgreedScanners: []string{"bearer", "semgrep"},
	}
	b, err := json.Marshal(corroborated)
	if err != nil {
		t.Fatal(err)
	}
	got := string(b)
	if !strings.Contains(got, `"agreedScanners":["bearer","semgrep"]`) {
		t.Errorf("expected agreedScanners in payload, got %s", got)
	}

	lone := triageFindingWire{ID: "semgrep-0", Title: "XSS", Severity: "medium"}
	b2, err := json.Marshal(lone)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b2), "agreedScanners") {
		t.Errorf("expected agreedScanners omitted for lone finding, got %s", string(b2))
	}
}
