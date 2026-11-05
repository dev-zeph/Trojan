package agent

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/dev-zeph/trojan/internal/greybox"
)

// fakeSource implements SourceReader, recording the request it received.
type fakeSource struct {
	got greybox.ReadSourceRequest
	res greybox.ReadSourceResult
}

func (f *fakeSource) ReadSource(req greybox.ReadSourceRequest) (greybox.ReadSourceResult, error) {
	f.got = req
	return f.res, nil
}

func TestRunReadSourceGreyBox(t *testing.T) {
	tb, _ := newTestbox(t, DefaultLimits(), http.NotFoundHandler())
	fs := &fakeSource{res: greybox.ReadSourceResult{
		Chunks:  []greybox.SourceChunk{{File: "app/api/users/[id]/route.ts", Line: 3, Symbol: "GET", Code: "db.query(\"...\" + id)"}},
		Summary: &greybox.StructuralSummary{RawQuery: true, HasAuthCheck: false},
	}}
	tb.SetSource(fs)

	tr := &fakeTransport{turns: []*TurnResult{
		turn("tool_use", toolUseBlock("r1", toolReadSource, greybox.ReadSourceRequest{
			Endpoint: &greybox.EndpointRef{Method: "GET", Path: "/api/users/5"},
		})),
		turn("tool_use", toolUseBlock("f1", toolFinish, map[string]any{"summary": "done"})),
	}}

	_, err := Run(context.Background(), tb, tr, RunOptions{Task: "go"})
	if err != nil {
		t.Fatal(err)
	}

	// The tool call reached the source reader with the right endpoint.
	if fs.got.Endpoint == nil || fs.got.Endpoint.Path != "/api/users/5" {
		t.Fatalf("source reader got %+v, want endpoint /api/users/5", fs.got)
	}
	// read_source must NOT consume the request budget (no target traffic).
	if _, reqs, _ := tb.Budget().Stats(); reqs != 0 {
		t.Errorf("read_source should cost 0 requests, got %d", reqs)
	}
	// The structural summary reached the model's tool_result.
	if len(tr.received) < 2 {
		t.Fatalf("expected a second turn")
	}
	last := tr.received[1]
	toolResult := string(last[len(last)-1].Content[0])
	if !strings.Contains(toolResult, "raw_query") || !strings.Contains(toolResult, "route.ts") {
		t.Errorf("tool_result missing grey-box context: %s", toolResult)
	}
}

func TestRunStreamsGraphDeltas(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("ok")) })
	tb, base := newTestbox(t, DefaultLimits(), mux) // seeds one endpoint node from the crawl ("/")

	var graphEvents []Event
	onEvt := func(e Event) {
		if e.Type == EventGraph {
			graphEvents = append(graphEvents, e)
		}
	}

	tr := &fakeTransport{turns: []*TurnResult{
		turn("tool_use", toolUseBlock("p1", toolHTTPProbe, ProbeRequest{Method: "GET", URL: base + "/"})),
		turn("tool_use",
			toolUseBlock("n1", toolNoteFinding, Candidate{Title: "Exposed root", Severity: "medium", URL: base + "/", Evidence: "ok"}),
			toolUseBlock("f1", toolFinish, map[string]any{"summary": "done"}),
		),
	}}

	_, err := Run(context.Background(), tb, tr, RunOptions{Task: "go", OnEvent: onEvt})
	if err != nil {
		t.Fatal(err)
	}

	// Should see: initial seed (untested), a testing transition, a vulnerable
	// transition, and a finding node.
	var sawUntested, sawTesting, sawVulnerable, sawFinding bool
	for _, e := range graphEvents {
		n := e.Payload.Node
		if n == nil {
			continue
		}
		switch {
		case n.Type == NodeFinding:
			sawFinding = true
		case n.Status == StatusUntested:
			sawUntested = true
		case n.Status == StatusTesting:
			sawTesting = true
		case n.Status == StatusVulnerable:
			sawVulnerable = true
		}
	}
	if !sawUntested || !sawTesting || !sawVulnerable || !sawFinding {
		t.Errorf("graph lifecycle incomplete: untested=%v testing=%v vulnerable=%v finding=%v (from %d graph events)",
			sawUntested, sawTesting, sawVulnerable, sawFinding, len(graphEvents))
	}
	// Final graph state: the endpoint is vulnerable.
	_, tested, vuln := tb.Graph().Counts()
	if tested < 1 || vuln < 1 {
		t.Errorf("expected the endpoint tested+vulnerable, got tested=%d vuln=%d", tested, vuln)
	}
}

func TestRunChainingFacts(t *testing.T) {
	tb, _ := newTestbox(t, DefaultLimits(), http.NotFoundHandler())
	// Seed two endpoint nodes the chain will connect.
	tb.Graph().UpsertEndpoint("POST", "/rest/user/login")
	tb.Graph().UpsertEndpoint("GET", "/api/orders/1")

	var graphEvents []Event
	onEvt := func(e Event) {
		if e.Type == EventGraph {
			graphEvents = append(graphEvents, e)
		}
	}

	tr := &fakeTransport{turns: []*TurnResult{
		turn("tool_use", toolUseBlock("m1", toolRememberFact, Fact{
			Kind: "token", Summary: "admin JWT via SQLi", Value: "eyJ...",
			From: "http://x/rest/user/login", Enables: "http://x/api/orders/1",
		})),
		turn("tool_use", toolUseBlock("f1", toolFinish, map[string]any{"summary": "done"})),
	}}

	_, err := Run(context.Background(), tb, tr, RunOptions{Task: "go", OnEvent: onEvt})
	if err != nil {
		t.Fatal(err)
	}

	// Fact was remembered.
	if facts := tb.Facts(); len(facts) != 1 || facts[0].Summary != "admin JWT via SQLi" {
		t.Fatalf("expected 1 remembered fact, got %+v", facts)
	}

	// Graph gained: a credential node, a dataflow edge (login -> cred), and a
	// chain edge (login -> orders) — the kill chain.
	var credNode bool
	var dataflowEdge, chainEdge bool
	for _, e := range graphEvents {
		if n := e.Payload.Node; n != nil && n.Type == NodeCredential {
			credNode = true
		}
		if ed := e.Payload.Edge; ed != nil {
			if ed.Kind == EdgeDataflow {
				dataflowEdge = true
			}
			if ed.Kind == EdgeChain {
				chainEdge = true
			}
		}
	}
	if !credNode || !dataflowEdge || !chainEdge {
		t.Errorf("chaining graph incomplete: credNode=%v dataflowEdge=%v chainEdge=%v", credNode, dataflowEdge, chainEdge)
	}
}

// countingSource returns a distinct handler for every distinct request, so each
// first-time read is "new ground"; a request it can't resolve yields a note with
// no chunks (as the real reader does when there is no code index).
type countingSource struct{ seen map[string]int }

func (c *countingSource) ReadSource(req greybox.ReadSourceRequest) (greybox.ReadSourceResult, error) {
	if c.seen == nil {
		c.seen = map[string]int{}
	}
	key := ""
	switch {
	case req.Endpoint != nil:
		key = req.Endpoint.Method + " " + req.Endpoint.Path
	case req.Symbol != "":
		key = "sym:" + req.Symbol
	}
	if key == "" { // e.g. a query with no index: no source resolved
		return greybox.ReadSourceResult{Note: "no code index"}, nil
	}
	if _, ok := c.seen[key]; !ok {
		c.seen[key] = len(c.seen) + 1
	}
	return greybox.ReadSourceResult{Chunks: []greybox.SourceChunk{{File: "routes.js", Line: c.seen[key]}}}, nil
}

// Reading distinct handlers is grey-box recon — new ground — so a run that reads
// source past the stall limit before probing must NOT be killed as stalled.
// Regression: a disciplined read-the-source-first pen test stopped at step 6
// with zero probes.
func TestRunReadingDistinctHandlersDefersStall(t *testing.T) {
	tb, _ := newTestbox(t, DefaultLimits(), http.NotFoundHandler())
	tb.SetSource(&countingSource{})

	var turns []*TurnResult
	for i := 0; i < StallSteps+2; i++ {
		turns = append(turns, turn("tool_use", toolUseBlock("r", toolReadSource, greybox.ReadSourceRequest{
			Endpoint: &greybox.EndpointRef{Method: "GET", Path: "/e" + strconv.Itoa(i)},
		})))
	}
	turns = append(turns, turn("tool_use", toolUseBlock("f", toolFinish, map[string]any{"summary": "done"})))

	res, err := Run(context.Background(), tb, &fakeTransport{turns: turns}, RunOptions{Task: "go"})
	if err != nil {
		t.Fatal(err)
	}
	if res.StopReason == StopStalled {
		t.Fatalf("run stalled after reading %d distinct handlers; grey-box recon should defer the stall guard", StallSteps+2)
	}
	if res.EndedBy != EventFinish {
		t.Errorf("EndedBy = %q, want finish", res.EndedBy)
	}
}

// A read that resolves to no source (e.g. a query with no code index) is not new
// ground, so a run doing only those must still stall — otherwise failed index
// lookups would mask a genuinely stuck agent.
func TestRunEmptyReadsStillStall(t *testing.T) {
	tb, _ := newTestbox(t, DefaultLimits(), http.NotFoundHandler())
	tb.SetSource(&countingSource{})

	query := turn("tool_use", toolUseBlock("q", toolReadSource, greybox.ReadSourceRequest{Query: "where is the auth check"}))
	var turns []*TurnResult
	for i := 0; i < 50; i++ {
		turns = append(turns, query)
	}
	res, err := Run(context.Background(), tb, &fakeTransport{turns: turns}, RunOptions{Task: "go"})
	if err != nil {
		t.Fatal(err)
	}
	if res.StopReason != StopStalled || res.Steps != StallSteps {
		t.Errorf("StopReason = %q Steps = %d, want %q after %d", res.StopReason, res.Steps, StopStalled, StallSteps)
	}
}

func TestRunReadSourceBlackBoxFallback(t *testing.T) {
	tb, _ := newTestbox(t, DefaultLimits(), http.NotFoundHandler())
	// No source set — read_source must degrade to a note, not error.
	tr := &fakeTransport{turns: []*TurnResult{
		turn("tool_use", toolUseBlock("r1", toolReadSource, greybox.ReadSourceRequest{Symbol: "getUser"})),
		turn("tool_use", toolUseBlock("f1", toolFinish, map[string]any{"summary": "done"})),
	}}
	_, err := Run(context.Background(), tb, tr, RunOptions{Task: "go"})
	if err != nil {
		t.Fatal(err)
	}
	last := tr.received[1]
	toolResult := string(last[len(last)-1].Content[0])
	if !strings.Contains(toolResult, "black-box") {
		t.Errorf("expected black-box fallback note, got: %s", toolResult)
	}
}
