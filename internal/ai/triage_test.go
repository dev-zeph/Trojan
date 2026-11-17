package ai

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/dev-zeph/trojan/internal/normalizer"
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

func TestGraphContextRendersReachFacts(t *testing.T) {
	// Unauthenticated, sensitive read → the facts the triage model needs.
	f := normalizer.Finding{Reach: &normalizer.ReachInfo{
		Reachable: true, Guarded: false,
		Entrypoints: []string{"GET /admin/reports/revenue.csv (routes/reports.js:15)"},
		Reads:       []string{"invoices", "clients"},
		Sensitive:   true, Categories: []string{"financial"},
	}}
	got := graphContext(f)
	for _, want := range []string{"PUBLIC entrypoint with NO login check", "reads: invoices, clients", "touches sensitive data (financial)"} {
		if !strings.Contains(got, want) {
			t.Errorf("graphContext missing %q in %q", want, got)
		}
	}
	// No graph node → empty, so the wire field is simply omitted.
	if graphContext(normalizer.Finding{}) != "" {
		t.Error("graphContext should be empty when Reach is nil")
	}
	// A guarded route must not read as unauthenticated.
	g := graphContext(normalizer.Finding{Reach: &normalizer.ReachInfo{Reachable: true, Guarded: true}})
	if strings.Contains(g, "NO login") {
		t.Errorf("guarded route wrongly marked unauthenticated: %q", g)
	}
}
