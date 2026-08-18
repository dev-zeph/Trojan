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

// Fact is something the agent learned during the run and may reuse to chain
// into a further attack — a captured credential/token, an object identifier, a
// trust relationship, or a missing check (§6.5 #5, state/memory). Facts are the
// pen-test-vs-scanner differentiator: they let the agent use step 3's discovery
// to attack in step 7, and the From→Enables links render as the attack graph's
// kill-chain edges (§9).
type Fact struct {
	Kind    string `json:"kind"`              // credential | token | identifier | endpoint | trust | observation
	Summary string `json:"summary"`           // human-readable ("admin JWT obtained via SQLi on /rest/user/login")
	Value   string `json:"value,omitempty"`   // the concrete token/id/cred, for reuse
	From    string `json:"from,omitempty"`    // URL/path this fact came from
	Enables string `json:"enables,omitempty"` // URL/path this fact could help attack (a chain step)
}

// Identity is a named authenticated session the agent can send probes as, for
// testing authorization boundaries — IDOR / BOLA (§6.5 #2). Headers (typically an
// Authorization bearer or a Cookie) are attached to a probe when the agent
// selects this identity. Supplied by the user; there is no login automation in
// v1, so any auth scheme works.
type Identity struct {
	Name    string            `json:"name"`
	Headers map[string]string `json:"headers"`
}

// ProbeRequest is a single constrained HTTP request the agent wants to send.
// JSON tags match the http_probe tool's input_schema in the agentic-dast edge
// function, so a tool_use block deserializes straight into this struct.
type ProbeRequest struct {
	Method  string            `json:"method"`
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers,omitempty"`
	Body    string            `json:"body,omitempty"`
	// Identity selects which supplied identity's auth headers to attach, so the
	// agent can send the same request as different users to test authorization.
	Identity string `json:"identity,omitempty"`
}

// ProbeResult is the safe-mode-bounded response handed back to the agent.
type ProbeResult struct {
	// ProbeID identifies this response in the toolbox's capture store so the agent
	// can diff it against another probe (diff_responses) without re-sending the
	// body. Only the most recent captures are retained (see maxRetainedProbes).
	ProbeID   int               `json:"probe_id"`
	Status    int               `json:"status"`
	Headers   map[string]string `json:"headers"`
	Body      string            `json:"body"`
	Truncated bool              `json:"truncated"`
	Elapsed   time.Duration     `json:"elapsed"`
}

// capturedProbe is a probe's request meta + response body retained for diffing
// (§6.5 #3). Kept internal — the agent only ever sees ProbeRef via a DiffResult.
type capturedProbe struct {
	id       int
	method   string
	url      string
	identity string
	status   int
	body     string
}

func (c capturedProbe) ref() ProbeRef {
	return ProbeRef{ProbeID: c.id, Method: c.method, URL: c.url, Identity: c.identity, Status: c.status}
}

// maxRetainedProbes bounds the diff store: only the N most recent probe bodies
// are kept so a long run can't accumulate hundreds of capped bodies in memory.
// Referencing an evicted id is an honest, adaptable tool error.
const maxRetainedProbes = 24

// Toolbox is the agent's sole interface to the outside world. Every method here
// corresponds to one of the tools in §3.3; there is no other way for the agent
// to act. It is safe for concurrent use.
type Toolbox struct {
	env        *Envelope
	budget     *Budget
	limiter    *RateLimiter
	crawl      dast.CrawlResult
	client     *http.Client
	maxResp    int64
	source     SourceReader        // grey-box source access; nil = black-box only
	graph      *AttackGraph        // live attack-graph / coverage map (§9)
	identities map[string]Identity // named auth sessions for IDOR/BOLA (§6.5 #2)
	identOrder []string            // identity insertion order, for stable listing
	approvals  *Approvals          // §8 runtime approval queue; nil = HITL off (auto-execute)

	mu       sync.Mutex
	findings []Candidate
	facts    []Fact
	finished bool
	summary  string

	// probe capture store for diff_responses (§6.5 #3). Bounded to the most
	// recent maxRetainedProbes; probeOrder is the eviction queue (oldest first).
	probeSeq   int
	probes     map[int]capturedProbe
	probeOrder []int
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
	g := NewAttackGraph()
	// Seed the graph with the crawl's endpoints so the coverage map is populated
	// before the first probe (§9.2).
	for _, e := range crawl.Endpoints {
		g.UpsertEndpoint(e.Method, pathOf(e.URL))
	}
	return &Toolbox{
		env:     env,
		budget:  budget,
		limiter: NewRateLimiter(limits.RequestsPerSec, nil, nil),
		crawl:   crawl,
		client:  client,
		maxResp: limits.MaxResponseBytes,
		graph:   g,
	}
}

// Graph returns the live attack graph the loop streams to the UI.
func (t *Toolbox) Graph() *AttackGraph { return t.graph }

// Budget exposes the run budget so the loop can BeginStep / read Stats.
func (t *Toolbox) Budget() *Budget { return t.budget }

// SetSource wires grey-box source access into the toolbox (composition root).
func (t *Toolbox) SetSource(s SourceReader) { t.source = s }

// SetApprovals enables §8 human-in-the-loop: state-changing/out-of-scope actions
// are gated through this queue instead of executing immediately. nil = off.
func (t *Toolbox) SetApprovals(a *Approvals) { t.approvals = a }

// Approvals returns the runtime approval queue (nil when HITL is off).
func (t *Toolbox) Approvals() *Approvals { return t.approvals }

// Envelope returns the run's safety envelope, so the loop can Classify an action.
func (t *Toolbox) Envelope() *Envelope { return t.env }

// SetIdentities registers the named auth sessions the agent may probe as.
func (t *Toolbox) SetIdentities(ids []Identity) {
	t.identities = make(map[string]Identity, len(ids))
	t.identOrder = t.identOrder[:0]
	for _, id := range ids {
		if id.Name == "" || len(id.Headers) == 0 {
			continue
		}
		if _, dup := t.identities[id.Name]; !dup {
			t.identOrder = append(t.identOrder, id.Name)
		}
		t.identities[id.Name] = id
	}
}

// IdentityNames returns the registered identity names, in supply order, for the
// run context handed to the agent.
func (t *Toolbox) IdentityNames() []string {
	out := make([]string, len(t.identOrder))
	copy(out, t.identOrder)
	return out
}

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
	// Resolve the requested identity (for IDOR/BOLA testing) before spending
	// budget, so an unknown identity is a cheap, adaptable tool error.
	var identityHeaders map[string]string
	if req.Identity != "" {
		id, ok := t.identities[req.Identity]
		if !ok {
			return nil, fmt.Errorf("unknown identity %q; available: %s", req.Identity, strings.Join(t.IdentityNames(), ", "))
		}
		identityHeaders = id.Headers
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
	// Identity auth first (the base session), then the agent's explicit headers
	// so a deliberate per-probe header can still override.
	for k, v := range identityHeaders {
		httpReq.Header.Set(k, v)
	}
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

	result := &ProbeResult{
		Status:    resp.StatusCode,
		Headers:   pickHeaders(resp.Header),
		Body:      string(raw),
		Truncated: truncated,
		Elapsed:   time.Since(start),
	}
	// Capture the response so the agent can diff it later by id (§6.5 #3). The
	// identity recorded is the one the probe was sent as (empty = anonymous).
	result.ProbeID = t.captureProbe(req.Method, req.URL, req.Identity, result.Status, result.Body)
	return result, nil
}

// captureProbe stores a response for later diffing and returns its id, evicting
// the oldest capture once the retention cap is exceeded. Safe for concurrent use.
func (t *Toolbox) captureProbe(method, url, identity string, status int, body string) int {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.probes == nil {
		t.probes = make(map[int]capturedProbe)
	}
	t.probeSeq++
	id := t.probeSeq
	t.probes[id] = capturedProbe{
		id: id, method: method, url: url, identity: identity, status: status, body: body,
	}
	t.probeOrder = append(t.probeOrder, id)
	if len(t.probeOrder) > maxRetainedProbes {
		evict := t.probeOrder[0]
		t.probeOrder = t.probeOrder[1:]
		delete(t.probes, evict)
	}
	return id
}

// DiffResponses compares two previously captured probes by id (§6.5 #3). It is
// the deterministic replacement for the agent eyeballing two response bodies: no
// network, so it costs the token budget (the returned diff) not the request
// budget. A missing id (never sent, or evicted from the bounded store) is a tool
// error the agent can recover from by re-sending the request.
func (t *Toolbox) DiffResponses(aID, bID int) (*DiffResult, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if aID == bID {
		return nil, fmt.Errorf("diff_responses needs two different probe ids (got %d twice)", aID)
	}
	a, ok := t.probes[aID]
	if !ok {
		return nil, fmt.Errorf("probe #%d is not available (only the most recent %d probes are retained); re-send the request to capture it", aID, maxRetainedProbes)
	}
	b, ok := t.probes[bID]
	if !ok {
		return nil, fmt.Errorf("probe #%d is not available (only the most recent %d probes are retained); re-send the request to capture it", bID, maxRetainedProbes)
	}
	res := diffResponses(a, b)
	return &res, nil
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

// RememberFact records a chaining fact and returns the full accumulated list, so
// the agent's working memory stays salient in the tool result it reads back.
func (t *Toolbox) RememberFact(f Fact) []Fact {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.facts = append(t.facts, f)
	out := make([]Fact, len(t.facts))
	copy(out, t.facts)
	return out
}

// Facts returns a copy of the chaining facts recorded so far.
func (t *Toolbox) Facts() []Fact {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]Fact, len(t.facts))
	copy(out, t.facts)
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
