package retest

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/dev-zeph/trojan/internal/dast/agent"
	"github.com/dev-zeph/trojan/internal/normalizer"
)

func hostOf(t *testing.T, raw string) string {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u.Hostname()
}

func newRetester(t *testing.T, host string) *Retester {
	t.Helper()
	r, err := New(Options{Host: host})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func finding(id string, p *normalizer.Proof) normalizer.Finding {
	return normalizer.Finding{ID: id, Title: id, Status: normalizer.StatusOpen, Proof: p}
}

// Reflection still present -> still vulnerable.
func TestRetestReflectionStillVulnerable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("echo: " + r.URL.Query().Get("q")))
	}))
	defer srv.Close()
	p := &normalizer.Proof{Method: "GET", URL: srv.URL + "/s?q=markerABCDEFG", OrigStatus: 200,
		Signal: normalizer.ProofSignal{Kind: normalizer.SignalReflection, Marker: "markerABCDEFG"}}

	res := newRetester(t, hostOf(t, srv.URL)).RetestFinding(context.Background(), finding("f1", p))
	if res.Verdict != Vulnerable {
		t.Fatalf("verdict = %q (%s), want still_vulnerable", res.Verdict, res.Reason)
	}
}

// Reflection gone (payload now escaped/absent) -> fixed.
func TestRetestReflectionFixed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("echo: [sanitized]"))
	}))
	defer srv.Close()
	p := &normalizer.Proof{Method: "GET", URL: srv.URL + "/s?q=markerABCDEFG", OrigStatus: 200,
		Signal: normalizer.ProofSignal{Kind: normalizer.SignalReflection, Marker: "markerABCDEFG"}}

	res := newRetester(t, hostOf(t, srv.URL)).RetestFinding(context.Background(), finding("f1", p))
	if res.Verdict != Fixed {
		t.Fatalf("verdict = %q (%s), want fixed", res.Verdict, res.Reason)
	}
}

// An endpoint that used to serve a 200 now returns 401 -> fixed.
func TestRetestStatusNowSecured(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()
	p := &normalizer.Proof{Method: "GET", URL: srv.URL + "/admin", OrigStatus: 200,
		Signal: normalizer.ProofSignal{Kind: normalizer.SignalStatus}}

	res := newRetester(t, hostOf(t, srv.URL)).RetestFinding(context.Background(), finding("f1", p))
	if res.Verdict != Fixed {
		t.Fatalf("verdict = %q (%s), want fixed", res.Verdict, res.Reason)
	}
	if res.NewStatus != 401 {
		t.Errorf("new status = %d, want 401", res.NewStatus)
	}
}

// Same status as before -> still vulnerable.
func TestRetestStatusStillVulnerable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		_, _ = w.Write([]byte("admin panel"))
	}))
	defer srv.Close()
	p := &normalizer.Proof{Method: "GET", URL: srv.URL + "/admin", OrigStatus: 200,
		Signal: normalizer.ProofSignal{Kind: normalizer.SignalStatus}}

	res := newRetester(t, hostOf(t, srv.URL)).RetestFinding(context.Background(), finding("f1", p))
	if res.Verdict != Vulnerable {
		t.Fatalf("verdict = %q (%s), want still_vulnerable", res.Verdict, res.Reason)
	}
}

// Open redirect removed -> fixed.
func TestRetestRedirectRemoved(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200) // no redirect anymore
	}))
	defer srv.Close()
	p := &normalizer.Proof{Method: "GET", URL: srv.URL + "/go?url=http://evil.test", OrigStatus: 302,
		Signal: normalizer.ProofSignal{Kind: normalizer.SignalRedirect, Marker: "http://evil.test"}}

	res := newRetester(t, hostOf(t, srv.URL)).RetestFinding(context.Background(), finding("f1", p))
	if res.Verdict != Fixed {
		t.Fatalf("verdict = %q (%s), want fixed", res.Verdict, res.Reason)
	}
}

// An unrecognized signal kind is inconclusive.
func TestRetestUnknownSignalInconclusive(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	defer srv.Close()
	p := &normalizer.Proof{Method: "GET", URL: srv.URL + "/x", OrigStatus: 200,
		Signal: normalizer.ProofSignal{Kind: "something-new"}}

	res := newRetester(t, hostOf(t, srv.URL)).RetestFinding(context.Background(), finding("f1", p))
	if res.Verdict != Inconclusive {
		t.Fatalf("verdict = %q (%s), want inconclusive", res.Verdict, res.Reason)
	}
}

// A finding with no recorded proof is inconclusive, with no network traffic.
func TestRetestNoProofInconclusive(t *testing.T) {
	r := newRetester(t, "example.test")
	res := r.RetestFinding(context.Background(), finding("f1", nil))
	if res.Verdict != Inconclusive {
		t.Fatalf("verdict = %q, want inconclusive", res.Verdict)
	}
}

// A proof whose URL is on another host is refused (never replayed).
func TestRetestOutOfScopeRefused(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("out-of-scope host must not be contacted")
	}))
	defer srv.Close()
	p := &normalizer.Proof{Method: "GET", URL: "http://other-host.test/x", OrigStatus: 200,
		Signal: normalizer.ProofSignal{Kind: normalizer.SignalStatus}}

	res := newRetester(t, hostOf(t, srv.URL)).RetestFinding(context.Background(), finding("f1", p))
	if res.Verdict != Inconclusive {
		t.Fatalf("verdict = %q (%s), want inconclusive (refused)", res.Verdict, res.Reason)
	}
}

// A finding that used an identity's credentials, with none supplied, is
// inconclusive ("needs a login") rather than replayed without auth.
func TestRetestIdentityNeeded(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("must not replay without the required credentials")
	}))
	defer srv.Close()
	p := &normalizer.Proof{Method: "GET", URL: srv.URL + "/me", OrigStatus: 200, Identity: "alice",
		RequestHeaders: map[string]string{"Authorization": normalizer.RedactedValue},
		Signal:         normalizer.ProofSignal{Kind: normalizer.SignalStatus}}

	res := newRetester(t, hostOf(t, srv.URL)).RetestFinding(context.Background(), finding("f1", p))
	if res.Verdict != Inconclusive {
		t.Fatalf("verdict = %q (%s), want inconclusive", res.Verdict, res.Reason)
	}
}

// Supplying the identity's credentials lets the retest run.
func TestRetestIdentitySupplied(t *testing.T) {
	var sawAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawAuth = r.Header.Get("Authorization")
		w.WriteHeader(200)
		_, _ = w.Write([]byte("your data")) // same status as before -> still vulnerable
	}))
	defer srv.Close()
	p := &normalizer.Proof{Method: "GET", URL: srv.URL + "/me", OrigStatus: 200, Identity: "alice",
		RequestHeaders: map[string]string{"Authorization": normalizer.RedactedValue},
		Signal:         normalizer.ProofSignal{Kind: normalizer.SignalStatus}}

	r, err := New(Options{Host: hostOf(t, srv.URL),
		Identities: map[string]agent.Identity{"alice": {Name: "alice", Headers: map[string]string{"Authorization": "Bearer real"}}}})
	if err != nil {
		t.Fatal(err)
	}
	res := r.RetestFinding(context.Background(), finding("f1", p))
	if res.Verdict != Vulnerable {
		t.Fatalf("verdict = %q (%s), want still_vulnerable", res.Verdict, res.Reason)
	}
	if sawAuth != "Bearer real" {
		t.Errorf("replay auth = %q, want restored from identity", sawAuth)
	}
}

// The rate limiter paces multiple replays (verified via injected clock/sleep).
func TestRetestRateLimited(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	defer srv.Close()

	now := time.Unix(0, 0)
	var slept time.Duration
	opts := Options{
		Host:           hostOf(t, srv.URL),
		RequestsPerSec: 2, // one every 500ms
		clock:          func() time.Time { return now },
		sleep:          func(d time.Duration) { slept += d; now = now.Add(d) },
	}
	r, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	mk := func(id string) normalizer.Finding {
		return finding(id, &normalizer.Proof{Method: "GET", URL: srv.URL + "/x", OrigStatus: 200,
			Signal: normalizer.ProofSignal{Kind: normalizer.SignalStatus}})
	}
	r.RetestFindings(context.Background(), []normalizer.Finding{mk("a"), mk("b"), mk("c")})
	// 3 requests at 2/s means two forced waits of ~500ms.
	if slept < 900*time.Millisecond {
		t.Errorf("rate limiter slept %s, expected it to pace replays", slept)
	}
}
