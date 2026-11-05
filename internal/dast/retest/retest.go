// Package retest re-checks a single website / DAST finding deterministically,
// with no AI tokens, by replaying the exact request recorded in the finding's
// Proof and comparing the response to the original signal. It is the "checking
// just the endpoints behind the open findings takes seconds" path (expert
// feedback #12): a fixed endpoint (now 401, no reflection, redirect removed) is
// reported fixed in seconds, a still-vulnerable one stays open, and anything it
// cannot decide honestly returns inconclusive and points to a full test.
//
// Every replay goes through the same safety machinery as a live pen test: the
// run's host scope and Rules of Engagement (internal/dast/agent.Envelope and
// roe.go) refuse off-host, denylisted, or dangerous requests, and a rate
// limiter paces the traffic. Consent for the target is assumed already recorded
// (a finding only exists because a test the user authorized produced it).
package retest

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/dev-zeph/trojan/internal/dast/agent"
	"github.com/dev-zeph/trojan/internal/normalizer"
)

// Verdict is the outcome of re-checking one finding.
type Verdict string

const (
	// Fixed — the original signal is gone (secured, no longer reflected, redirect removed).
	Fixed Verdict = "fixed"
	// Vulnerable — the original signal is still present; the finding stays open.
	Vulnerable Verdict = "still_vulnerable"
	// Inconclusive — no proof, an unrecognized signal, missing credentials, an
	// out-of-scope/refused request, or an unreachable endpoint. Run a full test.
	Inconclusive Verdict = "inconclusive"
)

// Result is one finding's retest outcome, JSON-ready for the desktop.
type Result struct {
	FindingID  string  `json:"finding_id"`
	Title      string  `json:"title,omitempty"`
	Verdict    Verdict `json:"verdict"`
	Reason     string  `json:"reason"`
	Signal     string  `json:"signal,omitempty"`
	OrigStatus int     `json:"orig_status,omitempty"`
	NewStatus  int     `json:"new_status,omitempty"`
}

// Options configures a Retester.
type Options struct {
	// Host is the scoped host of the website test (lowercased hostname). A proof
	// whose URL is on any other host is refused, same as a live probe would be.
	Host string
	// RoE layers the engagement's allow/denylist and auto-avoid on top of the
	// host floor. Zero value is the safe default.
	RoE agent.RoE
	// RequestsPerSec caps replay traffic (<= 0 uses a conservative default).
	RequestsPerSec float64
	// Client sends the replays (nil uses a 15s-timeout client that does not
	// follow redirects, so redirect signals are observed rather than chased).
	Client *http.Client
	// Identities supplies credentials, keyed by identity name, to restore the
	// redacted auth of a finding that was proven as a logged-in user. Without a
	// match, such a finding is inconclusive ("needs a login").
	Identities map[string]agent.Identity

	// clock and sleep are test hooks for the rate limiter; nil uses the wall clock.
	clock func() time.Time
	sleep func(time.Duration)
}

// Retester replays proofs under a fixed safety envelope and rate limit.
type Retester struct {
	opts    Options
	env     *agent.Envelope
	limiter *agent.RateLimiter
	client  *http.Client
}

// New builds a Retester for one website test's scope. The envelope permits the
// methods a proof could contain (GET/HEAD/OPTIONS and non-destructive POST)
// while keeping the host floor strict; destructive verbs are never replayable.
func New(opts Options) (*Retester, error) {
	host := strings.ToLower(strings.TrimSpace(opts.Host))
	if host == "" {
		return nil, fmt.Errorf("retest requires a scoped host")
	}
	// Safe-active + accept-side-effects so an originally-permitted POST can be
	// replayed; the host-scope check inside ValidateProbe is unchanged and still
	// refuses anything off-host.
	env, err := agent.NewEnvelope(agent.TierSafeActive, agent.EnvProduction, host, true)
	if err != nil {
		return nil, err
	}
	env.SetRoE(opts.RoE)

	rps := opts.RequestsPerSec
	if rps <= 0 {
		rps = 5
	}
	client := opts.Client
	if client == nil {
		client = &http.Client{
			Timeout: 15 * time.Second,
			// Do not follow redirects: a redirect is itself a signal to compare.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		}
	}
	return &Retester{
		opts:    opts,
		env:     env,
		limiter: agent.NewRateLimiter(rps, opts.clock, opts.sleep),
		client:  client,
	}, nil
}

// RetestFindings re-checks several findings in order, respecting the rate limit
// between replays. Findings without a replayable proof are reported inconclusive
// without any network traffic.
func (r *Retester) RetestFindings(ctx context.Context, findings []normalizer.Finding) []Result {
	out := make([]Result, 0, len(findings))
	for _, f := range findings {
		out = append(out, r.RetestFinding(ctx, f))
	}
	return out
}

// RetestFinding replays one finding's proof and returns the verdict.
func (r *Retester) RetestFinding(ctx context.Context, f normalizer.Finding) Result {
	res := Result{FindingID: f.ID, Title: f.Title}

	if f.Proof == nil {
		res.Verdict = Inconclusive
		if strings.HasPrefix(f.ID, "nuclei-") || f.Scanner == "nuclei" {
			res.Reason = "no recorded proof for this Nuclei finding — re-run the website test to confirm the fix"
		} else {
			res.Reason = "no recorded proof — run a full website test to confirm the fix"
		}
		return res
	}

	p := f.Proof
	res.Signal = p.Signal.Kind
	res.OrigStatus = p.OrigStatus

	// Same safety floor as a live probe: off-host, denylisted, or dangerous
	// requests are refused, never replayed.
	if disp := r.env.Classify(p.Method, p.URL, len(p.RequestBody)); disp.Action == agent.ActionBlock {
		res.Verdict = Inconclusive
		res.Reason = "refused: " + disp.Reason
		return res
	}

	headers, err := r.replayHeaders(p)
	if err != nil {
		res.Verdict = Inconclusive
		res.Reason = err.Error()
		return res
	}

	r.limiter.Wait()
	status, respHeaders, body, err := r.send(ctx, p.Method, p.URL, p.RequestBody, headers)
	if err != nil {
		res.Verdict = Inconclusive
		res.Reason = "could not reach the endpoint: " + err.Error()
		return res
	}
	res.NewStatus = status
	r.decide(&res, p, status, respHeaders, body)
	return res
}

// replayHeaders rebuilds the request headers to send. Non-secret headers are
// reused as recorded; a redacted secret is restored from the finding's identity
// when the caller supplied it, otherwise the retest cannot run.
func (r *Retester) replayHeaders(p *normalizer.Proof) (map[string]string, error) {
	out := map[string]string{}
	needCreds := false
	for k, v := range p.RequestHeaders {
		if v == normalizer.RedactedValue || normalizer.IsSecretHeader(k) {
			needCreds = true
			continue
		}
		out[k] = v
	}
	if needCreds {
		if p.Identity == "" {
			return nil, fmt.Errorf("this finding used credentials that weren't recorded; re-run a full test to confirm the fix")
		}
		id, ok := r.opts.Identities[p.Identity]
		if !ok || len(id.Headers) == 0 {
			return nil, fmt.Errorf("needs a login: supply the %q identity's headers to retest this finding", p.Identity)
		}
		for k, v := range id.Headers {
			out[k] = v
		}
	}
	return out, nil
}

// decide applies the deterministic comparison for the proof's signal kind.
func (r *Retester) decide(res *Result, p *normalizer.Proof, status int, respHeaders http.Header, body string) {
	switch p.Signal.Kind {
	case normalizer.SignalReflection:
		if p.Signal.Marker != "" && strings.Contains(body, p.Signal.Marker) {
			res.Verdict = Vulnerable
			res.Reason = fmt.Sprintf("the payload %q is still reflected in the response", truncate(p.Signal.Marker, 48))
		} else {
			res.Verdict = Fixed
			res.Reason = "the injected payload is no longer reflected in the response"
		}
	case normalizer.SignalRedirect:
		loc := respHeaders.Get("Location")
		if status >= 300 && status < 400 && loc != "" && redirectMatches(p.Signal.Marker, loc) {
			res.Verdict = Vulnerable
			res.Reason = "the endpoint still redirects to " + truncate(loc, 80)
		} else {
			res.Verdict = Fixed
			res.Reason = "the redirect is gone"
		}
	case normalizer.SignalStatus:
		switch {
		case status == p.OrigStatus:
			res.Verdict = Vulnerable
			res.Reason = fmt.Sprintf("the endpoint still returns %d", status)
		case status == http.StatusUnauthorized || status == http.StatusForbidden:
			res.Verdict = Fixed
			res.Reason = fmt.Sprintf("the endpoint now requires authorization (%d)", status)
		case status >= 300 && status < 400:
			res.Verdict = Fixed
			res.Reason = fmt.Sprintf("the endpoint now redirects (%d), likely to a login", status)
		default:
			res.Verdict = Inconclusive
			res.Reason = fmt.Sprintf("the response changed from %d to %d; run a full test to be sure", p.OrigStatus, status)
		}
	case normalizer.SignalMissingHeader:
		if p.Signal.Marker != "" && respHeaders.Get(p.Signal.Marker) != "" {
			res.Verdict = Fixed
			res.Reason = "the " + p.Signal.Marker + " header is now present"
		} else {
			res.Verdict = Vulnerable
			res.Reason = "the " + p.Signal.Marker + " header is still missing"
		}
	default:
		res.Verdict = Inconclusive
		res.Reason = fmt.Sprintf("the recorded signal %q can't be re-checked automatically; run a full test", p.Signal.Kind)
	}
}

// send performs one replay and returns the status, response headers, and a
// size-capped body. User-Agent marks it as an authorized scanner.
func (r *Retester) send(ctx context.Context, method, rawURL, body string, headers map[string]string) (int, http.Header, string, error) {
	var rdr io.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, strings.ToUpper(strings.TrimSpace(method)), rawURL, rdr)
	if err != nil {
		return 0, nil, "", err
	}
	req.Header.Set("User-Agent", "Trojan-DAST/1.0 (security scanner — authorized use only; retest)")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := r.client.Do(req)
	if err != nil {
		return 0, nil, "", err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1 MiB cap
	return resp.StatusCode, resp.Header, string(raw), nil
}

// redirectMatches reports whether a replayed Location still points at the
// originally-recorded redirect target.
func redirectMatches(original, got string) bool {
	original, got = strings.TrimSpace(original), strings.TrimSpace(got)
	if original == "" {
		return got != ""
	}
	if strings.EqualFold(original, got) || strings.Contains(got, original) {
		return true
	}
	// Compare by target when both are absolute URLs with a host.
	if ou, err := url.Parse(original); err == nil && ou.Host != "" {
		if gu, err := url.Parse(got); err == nil {
			return strings.EqualFold(ou.Host, gu.Host)
		}
	}
	return false
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
