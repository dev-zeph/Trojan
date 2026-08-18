package agent

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/dev-zeph/trojan/internal/dast"
	"github.com/dev-zeph/trojan/internal/greybox"
)

// SourceReader gives the agent read access to the target's own source — the
// grey-box flagship (§6.6). Implemented by *greybox.Source and wired in by the
// composition root; nil means no source is available and read_source degrades to
// a note (black-box fallback).
type SourceReader interface {
	ReadSource(req greybox.ReadSourceRequest) (greybox.ReadSourceResult, error)
}

const probeUserAgent = "Trojan-DAST/1.0 (security scanner — authorized use only)"

// responseHeaderAllowlist keeps ProbeResult small and PII-light: only headers
// useful for reasoning about a finding are surfaced to the agent.
var responseHeaderAllowlist = []string{
	"Content-Type", "Content-Length", "Server", "X-Powered-By",
	"Location", "WWW-Authenticate", "X-Frame-Options",
	"Content-Security-Policy", "Strict-Transport-Security",
	"Access-Control-Allow-Origin", "X-Content-Type-Options",
}

// Candidate is a vulnerability the agent flags via note_finding. It is anchored
// on evidence (a probe response) so downstream triage (Phase 1) can adversarially
// verify it rather than trusting the model's say-so.
type Candidate struct {
	Title     string `json:"title"`
	Severity  string `json:"severity"`
	URL       string `json:"url"`
	Evidence  string `json:"evidence"`
	Rationale string `json:"rationale"`
}

// ProbeRequest is a single constrained HTTP request the agent wants to send.
// JSON tags match the http_probe tool's input_schema in the agentic-dast edge
// function, so a tool_use block deserializes straight into this struct.
type ProbeRequest struct {
	Method  string            `json:"method"`
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers,omitempty"`
	Body    string            `json:"body,omitempty"`
}

// ProbeResult is the safe-mode-bounded response handed back to the agent.
type ProbeResult struct {
	Status    int               `json:"status"`
	Headers   map[string]string `json:"headers"`
	Body      string            `json:"body"`
	Truncated bool              `json:"truncated"`
	Elapsed   time.Duration     `json:"elapsed"`
}

// Toolbox is the agent's sole interface to the outside world. Every method here
// corresponds to one of the tools in §3.3; there is no other way for the agent
// to act. It is safe for concurrent use.
type Toolbox struct {
	env     *Envelope
	budget  *Budget
	limiter *RateLimiter
	crawl   dast.CrawlResult
	client  *http.Client
	maxResp int64
	source  SourceReader // grey-box source access; nil = black-box only

	mu       sync.Mutex
	findings []Candidate
	finished bool
	summary  string
}

// NewToolbox wires the tools to a safety envelope, a run budget, and the crawl
// map the deterministic pre-pass already produced.
func NewToolbox(env *Envelope, budget *Budget, limits Limits, crawl dast.CrawlResult) *Toolbox {
	maxRedirects := limits.MaxRedirects
	client := &http.Client{
		Timeout: limits.ProbeTimeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if maxRedirects > 0 && len(via) >= maxRedirects {
				return fmt.Errorf("stopped after %d redirects", maxRedirects)
			}
			// Never follow a redirect off the scoped host.
			if !strings.EqualFold(req.URL.Hostname(), env.Host) {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
	return &Toolbox{
		env:     env,
		budget:  budget,
		limiter: NewRateLimiter(limits.RequestsPerSec, nil, nil),
		crawl:   crawl,
		client:  client,
		maxResp: limits.MaxResponseBytes,
	}
}

// Budget exposes the run budget so the loop can BeginStep / read Stats.
func (t *Toolbox) Budget() *Budget { return t.budget }

// SetSource wires grey-box source access into the toolbox (composition root).
func (t *Toolbox) SetSource(s SourceReader) { t.source = s }

// ReadSource is the grey-box tool (§6.6): read the target's own source to form
// grounded hypotheses. No target traffic — it costs the token budget (the
// returned context), never the request budget, so it doesn't touch Budget's
// request cap. Degrades to an explanatory note when no source is available.
func (t *Toolbox) ReadSource(req greybox.ReadSourceRequest) (greybox.ReadSourceResult, error) {
	if t.source == nil {
		return greybox.ReadSourceResult{
			Note: "grey-box unavailable: no source indexed for this target — reason from the live responses (black-box).",
		}, nil
	}
	return t.source.ReadSource(req)
}

// GetCrawlMap returns the discovered endpoints/params/tech. Read-only, no
// network, no budget cost.
func (t *Toolbox) GetCrawlMap() dast.CrawlResult { return t.crawl }

// HTTPProbe sends one constrained HTTP request. It enforces (in order): safe-mode
// validation, the request budget, the global rate cap, then a size-capped read.
// Any safe-mode violation or tripped cap is returned as an error and no unsafe
// traffic is sent.
func (t *Toolbox) HTTPProbe(ctx context.Context, req ProbeRequest) (*ProbeResult, error) {
	if err := t.env.ValidateProbe(req.Method, req.URL, len(req.Body)); err != nil {
		return nil, err
	}
	if err := t.budget.CountRequest(); err != nil {
		return nil, err
	}
	t.limiter.Wait()

	var body io.Reader
	if req.Body != "" {
		body = strings.NewReader(req.Body)
	}
	httpReq, err := http.NewRequestWithContext(ctx, strings.ToUpper(strings.TrimSpace(req.Method)), req.URL, body)
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("User-Agent", probeUserAgent)
	for k, v := range req.Headers {
		httpReq.Header.Set(k, v)
	}

	start := time.Now()
	resp, err := t.client.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Read at most maxResp bytes; flag (never silently) if the body was longer.
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, t.maxResp+1))
	truncated := t.maxResp > 0 && int64(len(raw)) > t.maxResp
	if truncated {
		raw = raw[:t.maxResp]
	}

	return &ProbeResult{
		Status:    resp.StatusCode,
		Headers:   pickHeaders(resp.Header),
		Body:      string(raw),
		Truncated: truncated,
		Elapsed:   time.Since(start),
	}, nil
}

// NoteFinding records a candidate vulnerability. No network.
func (t *Toolbox) NoteFinding(c Candidate) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.findings = append(t.findings, c)
}

// Findings returns a copy of everything recorded so far.
func (t *Toolbox) Findings() []Candidate {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]Candidate, len(t.findings))
	copy(out, t.findings)
	return out
}

// Finish ends the run with a summary.
func (t *Toolbox) Finish(summary string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.finished = true
	t.summary = summary
}

// Finished reports whether the agent called finish, and its summary.
func (t *Toolbox) Finished() (bool, string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.finished, t.summary
}

func pickHeaders(h http.Header) map[string]string {
	out := map[string]string{}
	for _, k := range responseHeaderAllowlist {
		if v := h.Get(k); v != "" {
			out[k] = v
		}
	}
	return out
}
