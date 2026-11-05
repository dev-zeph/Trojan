package agent

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/dev-zeph/trojan/internal/graph"
)

func TestSaveLoadHypotheses(t *testing.T) {
	dir := t.TempDir()
	want := HypothesisFile{
		RunID: "r1",
		Hypotheses: []Hypothesis{{
			ID: "H1", Title: "Public order write",
			NodeKeys: []string{"app/api/orders/route.ts#POST", "datastore:orders"},
			Class:    "missing-auth", Method: "POST", Path: "/api/orders",
			ExpectedEvidence: "unauth POST returns 200", Confidence: "high",
		}},
	}
	if err := SaveHypotheses(dir, want); err != nil {
		t.Fatalf("save: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, ".trojan", "hypotheses.json")); err != nil {
		t.Fatalf("file not written: %v", err)
	}
	got, err := LoadHypotheses(dir)
	if err != nil || got == nil {
		t.Fatalf("load: %v (got %v)", err, got)
	}
	if len(got.Hypotheses) != 1 || got.Hypotheses[0].ID != "H1" {
		t.Fatalf("round-trip wrong: %+v", got)
	}
	// A missing file is (nil, nil), not an error.
	none, err := LoadHypotheses(t.TempDir())
	if err != nil || none != nil {
		t.Fatalf("missing file should be (nil,nil), got %v %v", none, err)
	}
}

// TestRun_SavesVibeappKeys drives the loop over the vibeapp order-write graph
// with a scripted transport and checks the emitted hypothesis references the
// correct stable node keys and can be saved to .trojan/hypotheses.json.
func TestRun_SavesVibeappKeys(t *testing.T) {
	g := graph.New()
	g.Nodes = []graph.Node{
		{ID: 0, Kind: graph.KindFunc, Key: "app/api/orders/route.ts#POST", Name: "POST", File: "app/api/orders/route.ts", Line: 3, Source: true},
		{ID: 1, Kind: graph.KindDataStore, Key: "datastore:orders", Name: "orders", File: "supabase/migrations/0001_init.sql", Line: 1},
	}
	g.Edges = []graph.Edge{{Src: 0, Dst: 1, Kind: graph.EdgeWrites}}
	tb := NewToolbox(g)

	hyp := map[string]any{
		"title":             "Unauthenticated order creation",
		"node_keys":         []string{"app/api/orders/route.ts#POST", "datastore:orders"},
		"class":             "missing-auth",
		"method":            "POST",
		"path":              "/api/orders",
		"expected_evidence": "a POST with no session cookie returns 200 and inserts a row into orders",
		"confidence":        "high",
	}
	tr := &scriptedTransport{turns: []*TurnResult{
		toolTurn(toolEmitHypothesis, hyp, "run-xyz"),
		toolTurn(toolFinish, map[string]string{"summary": "one missing-auth write"}, ""),
	}}
	res, err := Run(context.Background(), tb, tr, "seed", Options{})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(res.Hypotheses) != 1 {
		t.Fatalf("want 1 hypothesis, got %d", len(res.Hypotheses))
	}
	h := res.Hypotheses[0]
	wantKeys := map[string]bool{"app/api/orders/route.ts#POST": true, "datastore:orders": true}
	for _, k := range h.NodeKeys {
		if !wantKeys[k] {
			t.Fatalf("unexpected node key %q", k)
		}
		delete(wantKeys, k)
	}
	if len(wantKeys) != 0 {
		t.Fatalf("missing node keys: %v", wantKeys)
	}

	dir := t.TempDir()
	if err := SaveHypotheses(dir, HypothesisFile{RunID: res.RunID, Hypotheses: res.Hypotheses}); err != nil {
		t.Fatalf("save: %v", err)
	}
	got, _ := LoadHypotheses(dir)
	if got == nil || len(got.Hypotheses) != 1 || got.Hypotheses[0].Path != "/api/orders" {
		t.Fatalf("saved file wrong: %+v", got)
	}
}
