package agent

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/dev-zeph/trojan/internal/graph"
	"github.com/dev-zeph/trojan/internal/greybox"
	"github.com/dev-zeph/trojan/internal/memory"
)

// exposureGraph: one unguarded entrypoint writing a datastore, plus one
// client-side function reaching a privileged sink.
func exposureGraph() *graph.Graph {
	g := graph.New()
	g.Nodes = []graph.Node{
		{ID: 0, Kind: graph.KindFunc, Key: "app/api/orders/route.ts#POST", Name: "POST", File: "app/api/orders/route.ts", Line: 3, Source: true},
		{ID: 1, Kind: graph.KindDataStore, Key: "datastore:orders", Name: "orders", File: "db.sql", Line: 1},
		{ID: 2, Kind: graph.KindFunc, Key: "components/AdminPanel.tsx#AdminPanel", Name: "AdminPanel", File: "components/AdminPanel.tsx", Line: 5, ClientSide: true},
		{ID: 3, Kind: graph.KindSink, Key: "components/AdminPanel.tsx#AdminPanel@admin.delete#1", Name: "admin.delete", File: "components/AdminPanel.tsx", Line: 9, Severity: "high", SinkRule: "service-role client in browser code"},
	}
	g.Edges = []graph.Edge{
		{Src: 0, Dst: 1, Kind: graph.EdgeWrites},
		{Src: 2, Dst: 3, Kind: graph.EdgeContains},
	}
	return g
}

func TestUnguardedPaths(t *testing.T) {
	tb := NewToolbox(exposureGraph())
	rows := tb.UnguardedPaths()
	if len(rows) != 1 {
		t.Fatalf("want 1 unguarded entrypoint, got %+v", rows)
	}
	if rows[0].Entrypoint != "app/api/orders/route.ts#POST" {
		t.Fatalf("wrong entrypoint: %+v", rows[0])
	}
	if len(rows[0].Reaches) != 1 || rows[0].Reaches[0] != "writes datastore:orders" {
		t.Fatalf("wrong reaches: %+v", rows[0].Reaches)
	}
}

func TestClientExposures(t *testing.T) {
	tb := NewToolbox(exposureGraph())
	ce := tb.ClientExposures()
	if len(ce) != 1 || ce[0].Client != "components/AdminPanel.tsx#AdminPanel" {
		t.Fatalf("want one client exposure, got %+v", ce)
	}
}

func TestHasKey(t *testing.T) {
	tb := NewToolbox(exposureGraph())
	if !tb.HasKey("datastore:orders") {
		t.Fatal("datastore:orders should be a known key")
	}
	if tb.HasKey("app/api/ghost/route.ts#POST") {
		t.Fatal("invented key should not be known")
	}
}

// fakeSource returns a canned read_source result.
type fakeSource struct{ res greybox.ReadSourceResult }

func (f fakeSource) ReadSource(greybox.ReadSourceRequest) (greybox.ReadSourceResult, error) {
	return f.res, nil
}

func TestReadSourceDispatch(t *testing.T) {
	tb := NewToolbox(exposureGraph())
	// Without a source, it returns a note, not an error.
	out, err := tb.Dispatch(toolReadSource, json.RawMessage(`{"symbol":"POST"}`))
	if err != nil {
		t.Fatalf("read_source without source: %v", err)
	}
	var r greybox.ReadSourceResult
	_ = json.Unmarshal([]byte(out), &r)
	if r.Note == "" {
		t.Fatalf("want a note when no source reader, got %s", out)
	}

	tb.WithSource(fakeSource{res: greybox.ReadSourceResult{
		Chunks: []greybox.SourceChunk{{File: "app/api/orders/route.ts", Line: 3, Code: "export async function POST(req){ /* no auth */ }"}},
	}})
	out, err = tb.Dispatch(toolReadSource, json.RawMessage(`{"endpoint":{"method":"POST","path":"/api/orders"}}`))
	if err != nil {
		t.Fatalf("read_source with source: %v", err)
	}
	if len(out) == 0 || out == "{}" {
		t.Fatalf("want a chunk, got %s", out)
	}
}

// fakeHistory implements HistorySource.
type fakeHistory struct{ events []memory.Event }

func (f fakeHistory) All() ([]memory.Event, error) { return f.events, nil }

func TestSecurityHistoryDispatch(t *testing.T) {
	tb := NewToolbox(exposureGraph())
	// No history: an empty array, not an error.
	out, err := tb.Dispatch(toolSecurityHistory, json.RawMessage(`{}`))
	if err != nil || out != "[]" {
		t.Fatalf("empty history want [], got %q err %v", out, err)
	}

	tb.WithHistory(fakeHistory{events: []memory.Event{
		{Kind: memory.KindConfirmed, NodeKey: "datastore:orders", Title: "Public order write", Evidence: "proven", At: time.Now()},
		{Kind: memory.KindFalsePositive, NodeKey: "datastore:orders", Title: "not really", At: time.Now()},
	}})
	out, err = tb.Dispatch(toolSecurityHistory, json.RawMessage(`{"node_key":"datastore:orders"}`))
	if err != nil {
		t.Fatalf("history: %v", err)
	}
	var items []HistoryItem
	if err := json.Unmarshal([]byte(out), &items); err != nil {
		t.Fatalf("unmarshal history: %v", err)
	}
	if len(items) != 2 {
		t.Fatalf("want 2 history items, got %d: %s", len(items), out)
	}
}
