package agent

import (
	"context"
	"net/http"
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
