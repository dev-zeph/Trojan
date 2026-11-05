package agent

import (
	"context"
	"net/http"
	"testing"

	"github.com/dev-zeph/trojan/internal/normalizer"
)

// A finding records a replayable Proof from the probe that proved it, with the
// identity's auth value redacted but the identity name and the derived signal
// kept — so a later retest can replay it safely.
func TestNoteFindingCapturesProof(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/search", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		_, _ = w.Write([]byte("<h1>Results for " + r.URL.Query().Get("q") + "</h1>"))
	})
	tb, base := newTestbox(t, DefaultLimits(), mux)
	tb.SetIdentities([]Identity{{Name: "alice", Headers: map[string]string{"Authorization": "Bearer super-secret"}}})

	target := base + "/search?q=trojanXSS12345"
	res, err := tb.HTTPProbe(context.Background(), ProbeRequest{Method: "GET", URL: target, Identity: "alice"})
	if err != nil {
		t.Fatal(err)
	}

	tb.NoteFinding(Candidate{Title: "Reflected XSS", Severity: "high", URL: target,
		Evidence: "q is echoed unescaped", ProbeID: res.ProbeID})

	fs := tb.Findings()
	if len(fs) != 1 || fs[0].Proof == nil {
		t.Fatalf("expected one finding with a proof, got %+v", fs)
	}
	p := fs[0].Proof
	if p.Method != "GET" || p.URL != target {
		t.Errorf("proof request = %s %s", p.Method, p.URL)
	}
	if p.OrigStatus != 200 {
		t.Errorf("orig status = %d, want 200", p.OrigStatus)
	}
	if got := p.RequestHeaders["Authorization"]; got != normalizer.RedactedValue {
		t.Errorf("Authorization = %q, want redacted", got)
	}
	if p.Identity != "alice" {
		t.Errorf("identity = %q, want alice", p.Identity)
	}
	if p.Signal.Kind != normalizer.SignalReflection || p.Signal.Marker != "trojanXSS12345" {
		t.Errorf("signal = %+v, want reflection on trojanXSS12345", p.Signal)
	}
	if p.Signal.Detail != "q is echoed unescaped" {
		t.Errorf("signal detail = %q", p.Signal.Detail)
	}
}

// Without a ProbeID, the most recent probe to the same URL is used as the proof.
func TestNoteFindingUsesMostRecentProbe(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/admin", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		_, _ = w.Write([]byte("admin panel"))
	})
	tb, base := newTestbox(t, DefaultLimits(), mux)
	target := base + "/admin"
	if _, err := tb.HTTPProbe(context.Background(), ProbeRequest{Method: "GET", URL: target}); err != nil {
		t.Fatal(err)
	}
	tb.NoteFinding(Candidate{Title: "Unauth admin", URL: target, Evidence: "reachable anonymously"})

	fs := tb.Findings()
	if len(fs) != 1 || fs[0].Proof == nil {
		t.Fatalf("expected a proof from the most recent probe, got %+v", fs)
	}
	if fs[0].Proof.Signal.Kind != normalizer.SignalStatus {
		t.Errorf("signal = %q, want status", fs[0].Proof.Signal.Kind)
	}
}

// A finding noted with no matching probe keeps a nil Proof (retest -> inconclusive).
func TestNoteFindingNoProbe(t *testing.T) {
	tb, base := newTestbox(t, DefaultLimits(), http.NewServeMux())
	tb.NoteFinding(Candidate{Title: "hunch", URL: base + "/never-probed", Evidence: "guess"})
	fs := tb.Findings()
	if len(fs) != 1 || fs[0].Proof != nil {
		t.Fatalf("expected a finding with no proof, got %+v", fs)
	}
}
