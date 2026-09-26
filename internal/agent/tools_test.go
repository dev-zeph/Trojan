package agent

import (
	"encoding/json"
	"testing"

	"github.com/dev-zeph/trojan/internal/graph"
)

// fixtureGraph builds a small graph by hand so the tool tests are fully
// deterministic and independent of the Go parser. Layout:
//
//	node0 api.loginHandler (source) --contains--> node1 db.Query   (high)
//	                                \--calls-----> node2 api.lookup (PII)
//	                                                   \--contains--> node3 exec.Command (high)
//
// So loginHandler reaches db.Query in one hop, and exec.Command in two hops
// through a PII-touching function.
func fixtureGraph() *graph.Graph {
	g := graph.New()
	g.Nodes = []graph.Node{
		{ID: 0, Kind: graph.KindFunc, Name: "api.loginHandler", File: "api/login.go", Line: 10, Source: true},
		{ID: 1, Kind: graph.KindSink, Name: "db.Query", File: "api/login.go", Line: 14, SinkRule: "SQL query execution", Severity: "high"},
		{ID: 2, Kind: graph.KindFunc, Name: "api.lookup", File: "api/user.go", Line: 5, PII: true},
		{ID: 3, Kind: graph.KindSink, Name: "exec.Command", File: "api/user.go", Line: 9, SinkRule: "OS command execution", Severity: "high"},
	}
	g.Edges = []graph.Edge{
		{Src: 0, Dst: 1, Kind: graph.EdgeContains},
		{Src: 0, Dst: 2, Kind: graph.EdgeCalls},
		{Src: 2, Dst: 3, Kind: graph.EdgeContains},
	}
	return g
}

func TestListEntrypoints(t *testing.T) {
	tb := NewToolbox(fixtureGraph())
	got := tb.ListEntrypoints()
	if len(got) != 1 {
		t.Fatalf("want 1 entrypoint, got %d: %+v", len(got), got)
	}
	if got[0].ID != 0 || got[0].Name != "api.loginHandler" {
		t.Fatalf("wrong entrypoint: %+v", got[0])
	}
	if got[0].Location != "api/login.go:10" {
		t.Fatalf("want location api/login.go:10, got %q", got[0].Location)
	}
}

func TestGetPIINodes(t *testing.T) {
	tb := NewToolbox(fixtureGraph())
	got := tb.GetPIINodes()
	if len(got) != 1 || got[0].ID != 2 {
		t.Fatalf("want only node 2 flagged PII, got %+v", got)
	}
}

func TestNeighbors(t *testing.T) {
	tb := NewToolbox(fixtureGraph())

	calls, err := tb.Neighbors(0, "calls")
	if err != nil {
		t.Fatalf("neighbors calls: %v", err)
	}
	if len(calls) != 1 || calls[0].ID != 2 {
		t.Fatalf("want call neighbour node 2, got %+v", calls)
	}

	contains, err := tb.Neighbors(0, "contains")
	if err != nil {
		t.Fatalf("neighbors contains: %v", err)
	}
	if len(contains) != 1 || contains[0].ID != 1 {
		t.Fatalf("want contains neighbour node 1, got %+v", contains)
	}

	any, err := tb.Neighbors(0, "any")
	if err != nil {
		t.Fatalf("neighbors any: %v", err)
	}
	if len(any) != 2 {
		t.Fatalf("want 2 any-neighbours, got %+v", any)
	}

	if _, err := tb.Neighbors(0, "bogus"); err == nil {
		t.Fatal("want error for unknown edge kind, got nil")
	}
	if _, err := tb.Neighbors(99, "any"); err == nil {
		t.Fatal("want error for out-of-range node id, got nil")
	}
}

func TestReadContext(t *testing.T) {
	tb := NewToolbox(fixtureGraph())

	// Exact match wins.
	exact := tb.ReadContext("api.loginHandler")
	if len(exact) != 1 || exact[0].ID != 0 {
		t.Fatalf("exact read_context: got %+v", exact)
	}

	// Partial, case-insensitive fallback.
	partial := tb.ReadContext("LOGIN")
	if len(partial) != 1 || partial[0].ID != 0 {
		t.Fatalf("partial read_context: got %+v", partial)
	}

	if got := tb.ReadContext("nope"); got != nil {
		t.Fatalf("want nil for no match, got %+v", got)
	}
	if got := tb.ReadContext("  "); got != nil {
		t.Fatalf("want nil for blank symbol, got %+v", got)
	}
}

func TestGetDataflow(t *testing.T) {
	tb := NewToolbox(fixtureGraph())

	// One-hop route: loginHandler -> db.Query.
	direct, err := tb.GetDataflow(0, 1)
	if err != nil {
		t.Fatalf("dataflow 0->1: %v", err)
	}
	if !direct.Found || direct.Severity != "high" {
		t.Fatalf("want found high route, got %+v", direct)
	}
	if len(direct.Via) != 1 || direct.Via[0].Name != "api.loginHandler" {
		t.Fatalf("want via [loginHandler], got %+v", direct.Via)
	}
	if direct.TouchPII {
		t.Fatal("direct route should not touch PII")
	}

	// Two-hop route through a PII function: loginHandler -> lookup -> exec.Command.
	deep, err := tb.GetDataflow(0, 3)
	if err != nil {
		t.Fatalf("dataflow 0->3: %v", err)
	}
	if !deep.Found {
		t.Fatalf("want found route 0->3, got %+v", deep)
	}
	if len(deep.Via) != 2 || deep.Via[0].Name != "api.loginHandler" || deep.Via[1].Name != "api.lookup" {
		t.Fatalf("want via [loginHandler, lookup], got %+v", deep.Via)
	}
	if !deep.TouchPII {
		t.Fatal("deep route crosses a PII function, want TouchPII true")
	}

	// No route: node 1 is a sink, not a source, so nothing flows from it.
	none, err := tb.GetDataflow(1, 3)
	if err != nil {
		t.Fatalf("dataflow 1->3: %v", err)
	}
	if none.Found || none.Note == "" {
		t.Fatalf("want not-found with a note, got %+v", none)
	}

	// Invalid ids are errors, not panics.
	if _, err := tb.GetDataflow(0, 99); err == nil {
		t.Fatal("want error for bad sink id, got nil")
	}
	if _, err := tb.GetDataflow(99, 1); err == nil {
		t.Fatal("want error for bad source id, got nil")
	}
}

func TestToolSpecs(t *testing.T) {
	names := toolNames()
	want := []string{"get_dataflow", "get_pii_nodes", "list_entrypoints", "neighbors", "read_context"}
	if len(names) != len(want) {
		t.Fatalf("want %d tools, got %v", len(want), names)
	}
	for i := range want {
		if names[i] != want[i] {
			t.Fatalf("tool %d: want %q, got %q", i, want[i], names[i])
		}
	}
	// Every required field must be declared in that tool's properties.
	for _, s := range ToolSpecs() {
		for _, r := range s.Required {
			if _, ok := s.Properties[r]; !ok {
				t.Fatalf("tool %s requires %q but does not declare it", s.Name, r)
			}
		}
	}
}

func TestDispatch(t *testing.T) {
	tb := NewToolbox(fixtureGraph())

	// list_entrypoints -> JSON array with one node.
	out, err := tb.Dispatch("list_entrypoints", json.RawMessage(`{}`))
	if err != nil {
		t.Fatalf("dispatch list_entrypoints: %v", err)
	}
	var eps []NodeView
	if err := json.Unmarshal([]byte(out), &eps); err != nil {
		t.Fatalf("unmarshal entrypoints: %v", err)
	}
	if len(eps) != 1 || eps[0].ID != 0 {
		t.Fatalf("dispatch entrypoints: got %s", out)
	}

	// get_dataflow through Dispatch with typed input.
	out, err = tb.Dispatch("get_dataflow", json.RawMessage(`{"source_id":0,"sink_id":3}`))
	if err != nil {
		t.Fatalf("dispatch get_dataflow: %v", err)
	}
	var df DataflowResult
	if err := json.Unmarshal([]byte(out), &df); err != nil {
		t.Fatalf("unmarshal dataflow: %v", err)
	}
	if !df.Found || !df.TouchPII {
		t.Fatalf("dispatch dataflow: got %s", out)
	}

	// neighbors through Dispatch.
	out, err = tb.Dispatch("neighbors", json.RawMessage(`{"node_id":0,"edge_kind":"contains"}`))
	if err != nil {
		t.Fatalf("dispatch neighbors: %v", err)
	}
	var nb []NodeView
	if err := json.Unmarshal([]byte(out), &nb); err != nil {
		t.Fatalf("unmarshal neighbors: %v", err)
	}
	if len(nb) != 1 || nb[0].ID != 1 {
		t.Fatalf("dispatch neighbors: got %s", out)
	}

	// Unknown tool and malformed input are errors, not panics.
	if _, err := tb.Dispatch("does_not_exist", json.RawMessage(`{}`)); err == nil {
		t.Fatal("want error for unknown tool, got nil")
	}
	if _, err := tb.Dispatch("get_dataflow", json.RawMessage(`{bad json`)); err == nil {
		t.Fatal("want error for malformed input, got nil")
	}
}

func TestParseFinding(t *testing.T) {
	f, err := parseFinding(json.RawMessage(`{"hypothesis":"SQLi in login","severity":"high","path":["api.loginHandler","db.Query"],"rationale":"concatenated query","source_id":0,"sink_id":1}`))
	if err != nil {
		t.Fatalf("parseFinding: %v", err)
	}
	if f.Hypothesis == "" || f.Severity != "high" || len(f.Path) != 2 || f.SinkID != 1 {
		t.Fatalf("parseFinding wrong result: %+v", f)
	}

	// Empty hypothesis is rejected.
	if _, err := parseFinding(json.RawMessage(`{"hypothesis":"  ","severity":"high"}`)); err == nil {
		t.Fatal("want error for empty hypothesis, got nil")
	}

	// Missing severity defaults to low.
	f2, err := parseFinding(json.RawMessage(`{"hypothesis":"x"}`))
	if err != nil {
		t.Fatalf("parseFinding default severity: %v", err)
	}
	if f2.Severity != "low" {
		t.Fatalf("want default severity low, got %q", f2.Severity)
	}
}
