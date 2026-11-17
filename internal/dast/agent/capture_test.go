package agent

import (
	"context"
	"net/http"
	"strings"
	"testing"
)

// TestAutoCaptureSetCookie proves a session cookie the target issues is
// auto-registered as a named identity and can then be replayed by name.
func TestAutoCaptureSetCookie(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "session", Value: "s3cr3t-session-value"})
		_, _ = w.Write([]byte(`{"ok":true}`))
	})
	// An endpoint that only answers to the captured session.
	mux.HandleFunc("/me", func(w http.ResponseWriter, r *http.Request) {
		if c, _ := r.Cookie("session"); c != nil && c.Value == "s3cr3t-session-value" {
			_, _ = w.Write([]byte(`{"user":"admin"}`))
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
	})
	tb, base := newTestbox(t, DefaultLimits(), mux)

	res, err := tb.HTTPProbe(context.Background(), ProbeRequest{Method: "GET", URL: base + "/login"})
	if err != nil {
		t.Fatal(err)
	}
	if res.CapturedIdentity != "captured-1" {
		t.Fatalf("expected captured-1, got %q (from %q)", res.CapturedIdentity, res.CapturedFrom)
	}
	if len(res.AvailableIdentities) != 1 || res.AvailableIdentities[0] != "captured-1" {
		t.Errorf("available_identities = %v, want [captured-1]", res.AvailableIdentities)
	}

	// Replay the captured session by name — the auth header must be attached.
	me, err := tb.HTTPProbe(context.Background(), ProbeRequest{Method: "GET", URL: base + "/me", Identity: "captured-1"})
	if err != nil {
		t.Fatal(err)
	}
	if me.Status != 200 || !strings.Contains(me.Body, `"user":"admin"`) {
		t.Errorf("replaying captured-1 failed: %d %q", me.Status, me.Body)
	}
}

// TestAutoCaptureSetCookieOnRedirect proves a session set on a login redirect
// (302 Set-Cookie -> Location) is retained across the hop and captured. This is
// the Meridian lab case: without a per-probe cookie jar the cookie was dropped
// when the client followed the redirect, so authenticated chains (IDOR, admin
// routes) could never be proved live.
func TestAutoCaptureSetCookieOnRedirect(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "mrd_session", Value: "forged-admin-session-value", Path: "/"})
		http.Redirect(w, r, "/portal", http.StatusFound) // 302, as a real login does
	})
	// The post-login page only renders with the session the 302 handed out.
	mux.HandleFunc("/portal", func(w http.ResponseWriter, r *http.Request) {
		if c, _ := r.Cookie("mrd_session"); c != nil && c.Value == "forged-admin-session-value" {
			_, _ = w.Write([]byte(`{"portal":"welcome admin"}`))
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
	})
	tb, base := newTestbox(t, DefaultLimits(), mux)

	res, err := tb.HTTPProbe(context.Background(), ProbeRequest{Method: "POST", URL: base + "/login"})
	if err != nil {
		t.Fatal(err)
	}
	// The followed redirect must have carried the cookie: we land on the authed page.
	if res.Status != 200 || !strings.Contains(res.Body, "welcome admin") {
		t.Errorf("redirect didn't carry the session cookie: %d %q", res.Status, res.Body)
	}
	// And the session the 302 set must be captured for replay on other endpoints.
	if res.CapturedIdentity != "captured-1" {
		t.Fatalf("session set on the 302 was not captured, got %q (from %q)", res.CapturedIdentity, res.CapturedFrom)
	}
}

// TestAutoCaptureDedup proves the same session isn't registered twice.
func TestAutoCaptureDedup(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "auth_token", Value: "same-value-every-time"})
	})
	tb, base := newTestbox(t, DefaultLimits(), mux)

	first, _ := tb.HTTPProbe(context.Background(), ProbeRequest{Method: "GET", URL: base + "/login"})
	if first.CapturedIdentity != "captured-1" {
		t.Fatalf("first login should capture, got %q", first.CapturedIdentity)
	}
	second, _ := tb.HTTPProbe(context.Background(), ProbeRequest{Method: "GET", URL: base + "/login"})
	if second.CapturedIdentity != "" {
		t.Errorf("identical session should not re-register, got %q", second.CapturedIdentity)
	}
	if names := tb.IdentityNames(); len(names) != 1 {
		t.Errorf("expected exactly 1 identity after dedup, got %v", names)
	}
}

// TestAutoCaptureIgnoresNonSessionCookie proves ordinary cookies (analytics,
// CSRF) don't become identities — only auth-looking sessions do.
func TestAutoCaptureIgnoresNonSessionCookie(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "_ga", Value: "GA1.2.analytics.value"})
		http.SetCookie(w, &http.Cookie{Name: "csrf_token", Value: "csrf-not-a-session-xyz"})
	})
	tb, base := newTestbox(t, DefaultLimits(), mux)

	res, _ := tb.HTTPProbe(context.Background(), ProbeRequest{Method: "GET", URL: base + "/"})
	if res.CapturedIdentity != "" {
		t.Errorf("non-session cookies should not be captured, got %q", res.CapturedIdentity)
	}
}

// TestAutoCaptureBearerFromBody proves a token handed back in a JSON body is
// captured as a Bearer identity.
func TestAutoCaptureBearerFromBody(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/login", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"eyJhbGci.payload.signature","role":"admin"}`))
	})
	tb, base := newTestbox(t, DefaultLimits(), mux)

	res, err := tb.HTTPProbe(context.Background(), ProbeRequest{Method: "GET", URL: base + "/api/login"})
	if err != nil {
		t.Fatal(err)
	}
	if res.CapturedIdentity != "captured-1" {
		t.Fatalf("expected a captured bearer identity, got %q", res.CapturedIdentity)
	}
	id, ok := tb.lookupIdentity("captured-1")
	if !ok || id.Headers["Authorization"] != "Bearer eyJhbGci.payload.signature" {
		t.Errorf("captured bearer header wrong: %+v", id)
	}
}

// TestCaptureFromFact proves a remembered credential/token becomes an identity.
func TestCaptureFromFact(t *testing.T) {
	tb, _ := newTestbox(t, DefaultLimits(), http.NotFoundHandler())

	name, _ := tb.CaptureFromFact(Fact{Kind: "token", Summary: "admin jwt via SQLi", Value: "header.body.sig"})
	if name != "captured-1" {
		t.Fatalf("token fact should register, got %q", name)
	}
	id, ok := tb.lookupIdentity("captured-1")
	if !ok || id.Headers["Authorization"] != "Bearer header.body.sig" {
		t.Errorf("fact-captured identity wrong: %+v", id)
	}
	// A short or non-cred fact must not register.
	if n, _ := tb.CaptureFromFact(Fact{Kind: "observation", Summary: "stack trace", Value: "x"}); n != "" {
		t.Errorf("observation fact should not register, got %q", n)
	}
}

// TestRedactSecretsFromReport proves identity secrets (supplied or captured) are
// scrubbed from the findings/facts that get persisted, while the live run keeps
// the real values.
func TestRedactSecretsFromReport(t *testing.T) {
	tb, _ := newTestbox(t, DefaultLimits(), http.NotFoundHandler())
	tb.SetIdentities([]Identity{
		{Name: "admin", Headers: map[string]string{"Authorization": "Bearer super-secret-admin-token"}},
	})

	findings := []Candidate{{
		Title:     "Auth bypass",
		Evidence:  "logged in with Bearer super-secret-admin-token and got 200",
		Rationale: "token super-secret-admin-token should not have worked",
	}}
	red := tb.RedactCandidates(findings)
	if strings.Contains(red[0].Evidence, "super-secret-admin-token") || strings.Contains(red[0].Rationale, "super-secret-admin-token") {
		t.Errorf("secret leaked into redacted finding: %+v", red[0])
	}
	if !strings.Contains(red[0].Evidence, redactedMark) {
		t.Errorf("expected redaction mark in evidence: %q", red[0].Evidence)
	}
	// The input slice must be untouched (live run still has the real value).
	if !strings.Contains(findings[0].Evidence, "super-secret-admin-token") {
		t.Error("RedactCandidates must not mutate the input")
	}

	facts := []Fact{{Kind: "token", Summary: "admin token", Value: "super-secret-admin-token"}}
	rf := tb.RedactFacts(facts)
	if rf[0].Value == "super-secret-admin-token" {
		t.Error("fact value should be redacted")
	}
}

// TestRunRedactsCapturedSecretFromReport is the end-to-end proof: the agent
// captures a session, notes a finding whose evidence quotes the secret, then the
// RunResult the report is built from has that secret scrubbed — while the live
// tool_result the model saw kept it.
func TestRunRedactsCapturedSecretFromReport(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "session", Value: "leak-me-not-token"})
	})
	tb, base := newTestbox(t, DefaultLimits(), mux)

	tr := &fakeTransport{turns: []*TurnResult{
		turn("tool_use", toolUseBlock("p1", toolHTTPProbe, ProbeRequest{Method: "GET", URL: base + "/login"})),
		turn("tool_use",
			toolUseBlock("n1", toolNoteFinding, Candidate{
				Title: "Weak session", Severity: "high", URL: base + "/login",
				Evidence: "server issued session=leak-me-not-token with no flags",
			}),
			toolUseBlock("f1", toolFinish, map[string]any{"summary": "1 finding"}),
		),
	}}

	res, err := Run(context.Background(), tb, tr, RunOptions{Task: "go"})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("want 1 finding, got %d", len(res.Findings))
	}
	if strings.Contains(res.Findings[0].Evidence, "leak-me-not-token") {
		t.Errorf("captured secret leaked into report finding: %q", res.Findings[0].Evidence)
	}
	if !strings.Contains(res.Findings[0].Evidence, redactedMark) {
		t.Errorf("expected redaction mark in report finding: %q", res.Findings[0].Evidence)
	}
	// The toolbox's own (un-persisted) findings keep the real value the agent
	// reasoned over — only the RunResult handed to the report is redacted.
	if !strings.Contains(tb.Findings()[0].Evidence, "leak-me-not-token") {
		t.Error("live findings should keep the real value; only the report is redacted")
	}
	// And the session was auto-registered so a re-test could replay it.
	if names := tb.IdentityNames(); len(names) != 1 || names[0] != "captured-1" {
		t.Errorf("expected captured-1 registered, got %v", names)
	}
}

// TestRedactNoopWithoutIdentities proves redaction leaves reports untouched when
// no identities carry a secret (the common single-identity run).
func TestRedactNoopWithoutIdentities(t *testing.T) {
	tb, _ := newTestbox(t, DefaultLimits(), http.NotFoundHandler())
	in := []Candidate{{Title: "X", Evidence: "Bearer whatever-text"}}
	if out := tb.RedactCandidates(in); out[0].Evidence != "Bearer whatever-text" {
		t.Errorf("no identities → no redaction, got %q", out[0].Evidence)
	}
}
