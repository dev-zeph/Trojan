package agent

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/dev-zeph/trojan/internal/dast"
)

// newTestbox spins up a live server and a Toolbox scoped to its host.
func newTestbox(t *testing.T, lim Limits, handler http.Handler) (*Toolbox, string) {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	env, err := NewEnvelope(TierSafeActive, EnvStaging, u.Hostname(), false)
	if err != nil {
		t.Fatal(err)
	}
	crawl := dast.CrawlResult{
		Endpoints: []dast.Endpoint{{URL: srv.URL + "/", Method: "GET"}},
		TechHints: []string{"nextjs"},
	}
	return NewToolbox(env, NewBudget(lim, nil), lim, crawl), srv.URL
}

func TestHTTPProbeBasic(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/hello", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "test-server")
		w.Header().Set("Set-Cookie", "secret=should-not-leak") // not in allowlist
		w.WriteHeader(200)
		_, _ = w.Write([]byte("hello world"))
	})
	tb, base := newTestbox(t, DefaultLimits(), mux)

	res, err := tb.HTTPProbe(context.Background(), ProbeRequest{Method: "GET", URL: base + "/hello"})
	if err != nil {
		t.Fatalf("probe failed: %v", err)
	}
	if res.Status != 200 || res.Body != "hello world" {
		t.Errorf("unexpected result: status=%d body=%q", res.Status, res.Body)
	}
	if res.Headers["Server"] != "test-server" {
		t.Errorf("Server header not surfaced: %v", res.Headers)
	}
	if _, leaked := res.Headers["Set-Cookie"]; leaked {
		t.Error("Set-Cookie should not be surfaced (not in allowlist)")
	}
	if res.Truncated {
		t.Error("small body should not be truncated")
	}
}

func TestHTTPProbeTruncation(t *testing.T) {
	big := strings.Repeat("A", 5000)
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(big))
	})
	lim := DefaultLimits()
	lim.MaxResponseBytes = 1000
	tb, base := newTestbox(t, lim, mux)

	res, err := tb.HTTPProbe(context.Background(), ProbeRequest{Method: "GET", URL: base + "/"})
	if err != nil {
		t.Fatalf("probe failed: %v", err)
	}
	if !res.Truncated {
		t.Error("oversized response should be flagged truncated")
	}
	if len(res.Body) != 1000 {
		t.Errorf("body should be capped at 1000 bytes, got %d", len(res.Body))
	}
}

func TestHTTPProbeSafeModeRejections(t *testing.T) {
	tb, base := newTestbox(t, DefaultLimits(), http.NotFoundHandler())

	// Destructive verb — rejected before any network.
	if _, err := tb.HTTPProbe(context.Background(), ProbeRequest{Method: "DELETE", URL: base + "/"}); err == nil {
		t.Error("DELETE should be rejected by safe-mode")
	}
	// Off-host — rejected before any network.
	if _, err := tb.HTTPProbe(context.Background(), ProbeRequest{Method: "GET", URL: "https://evil.example.com/"}); err == nil {
		t.Error("off-host probe should be rejected")
	}
}

func TestHTTPProbeRequestBudget(t *testing.T) {
	lim := DefaultLimits()
	lim.MaxRequests = 1
	lim.RequestsPerSec = 0 // don't slow the test
	tb, base := newTestbox(t, lim, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))

	if _, err := tb.HTTPProbe(context.Background(), ProbeRequest{Method: "GET", URL: base + "/"}); err != nil {
		t.Fatalf("first probe: %v", err)
	}
	_, err := tb.HTTPProbe(context.Background(), ProbeRequest{Method: "GET", URL: base + "/"})
	var be *BudgetError
	if !errors.As(err, &be) || be.Reason != StopRequestBudget {
		t.Fatalf("second probe should trip request budget, got %v", err)
	}
}

func TestNoteFindingAndFinish(t *testing.T) {
	tb, _ := newTestbox(t, DefaultLimits(), http.NotFoundHandler())

	if cm := tb.GetCrawlMap(); len(cm.Endpoints) != 1 || len(cm.TechHints) != 1 {
		t.Errorf("GetCrawlMap returned unexpected map: %+v", cm)
	}

	tb.NoteFinding(Candidate{Title: "Exposed /ftp", Severity: "medium", URL: "http://h/ftp"})
	tb.NoteFinding(Candidate{Title: "Stack trace", Severity: "low"})
	if got := tb.Findings(); len(got) != 2 {
		t.Errorf("expected 2 findings, got %d", len(got))
	}

	if fin, _ := tb.Finished(); fin {
		t.Error("should not be finished yet")
	}
	tb.Finish("done — 2 candidates")
	if fin, sum := tb.Finished(); !fin || sum != "done — 2 candidates" {
		t.Errorf("Finished() = %v, %q", fin, sum)
	}
}
