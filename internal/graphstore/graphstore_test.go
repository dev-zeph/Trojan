package graphstore

import (
	"path/filepath"
	"reflect"
	"sort"
	"testing"

	"github.com/dev-zeph/trojan/internal/graph"
)

// buildSampleGraph constructs a small graph by hand (mirroring what
// internal/graph.Build would produce): one HTTP-reachable source function
// that calls a sink, plus an ordinary function with no tags, to exercise
// every persisted field including Tags.
func buildSampleGraph() *graph.Graph {
	g := graph.New()

	g.Nodes = []graph.Node{
		{
			ID:     0,
			Kind:   graph.KindFunc,
			Name:   "handlers.HandleUpload",
			File:   "handlers/upload.go",
			Line:   42,
			Source: true,
			PII:    true,
			Tags: map[string]string{
				"sensitive_data_category": "PHI",
				"trust_boundary":          "public API",
			},
		},
		{
			ID:       1,
			Kind:     graph.KindSink,
			Name:     "exec.Command",
			File:     "handlers/upload.go",
			Line:     58,
			SinkRule: "os/exec with tainted argument",
			Severity: "high",
		},
		{
			ID:   2,
			Kind: graph.KindFunc,
			Name: "util.Trim",
			File: "util/strings.go",
			Line: 10,
			// No tags: exercises the nil-map round trip.
		},
	}

	g.Edges = []graph.Edge{
		{Src: 0, Dst: 1, Kind: graph.EdgeContains},
		{Src: 0, Dst: 2, Kind: graph.EdgeCalls},
	}

	return g
}

func sortNodes(nodes []graph.Node) {
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].ID < nodes[j].ID })
}

func sortEdges(edges []graph.Edge) {
	sort.Slice(edges, func(i, j int) bool {
		if edges[i].Src != edges[j].Src {
			return edges[i].Src < edges[j].Src
		}
		return edges[i].Dst < edges[j].Dst
	})
}

func TestSaveLoadRoundTrip(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "graph.db")

	want := buildSampleGraph()

	if err := Save(dbPath, want); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	got, err := Load(dbPath)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	sortNodes(want.Nodes)
	sortNodes(got.Nodes)
	sortEdges(want.Edges)
	sortEdges(got.Edges)

	if !reflect.DeepEqual(want.Nodes, got.Nodes) {
		t.Errorf("nodes mismatch:\n want=%+v\n got =%+v", want.Nodes, got.Nodes)
	}
	if !reflect.DeepEqual(want.Edges, got.Edges) {
		t.Errorf("edges mismatch:\n want=%+v\n got =%+v", want.Edges, got.Edges)
	}

	// Spot-check the fields that matter most for downstream reasoning:
	// source/sink flags, PII, and the org-authored Tags overlay.
	var handler, sink, util graph.Node
	for _, n := range got.Nodes {
		switch n.Name {
		case "handlers.HandleUpload":
			handler = n
		case "exec.Command":
			sink = n
		case "util.Trim":
			util = n
		}
	}

	if !handler.Source || !handler.PII {
		t.Errorf("handler node lost Source/PII flags: %+v", handler)
	}
	wantTags := map[string]string{
		"sensitive_data_category": "PHI",
		"trust_boundary":          "public API",
	}
	if !reflect.DeepEqual(handler.Tags, wantTags) {
		t.Errorf("handler tags mismatch: got %+v, want %+v", handler.Tags, wantTags)
	}
	if sink.SinkRule != "os/exec with tainted argument" || sink.Severity != "high" {
		t.Errorf("sink node lost SinkRule/Severity: %+v", sink)
	}
	if util.Tags != nil {
		t.Errorf("util node should have nil Tags after round trip, got %+v", util.Tags)
	}
}

func TestLoadMissingDatabaseReturnsEmptyGraph(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "does-not-exist", "graph.db")

	g, err := Load(dbPath)
	if err != nil {
		t.Fatalf("Load() on missing db error = %v", err)
	}
	if len(g.Nodes) != 0 || len(g.Edges) != 0 {
		t.Errorf("expected empty graph, got %d nodes, %d edges", len(g.Nodes), len(g.Edges))
	}
}

func TestSaveReplacesExistingData(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "graph.db")

	first := buildSampleGraph()
	if err := Save(dbPath, first); err != nil {
		t.Fatalf("first Save() error = %v", err)
	}

	second := graph.New()
	second.Nodes = []graph.Node{
		{ID: 0, Kind: graph.KindFunc, Name: "only.Func", File: "only.go", Line: 1},
	}

	if err := Save(dbPath, second); err != nil {
		t.Fatalf("second Save() error = %v", err)
	}

	got, err := Load(dbPath)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if len(got.Nodes) != 1 || got.Nodes[0].Name != "only.Func" {
		t.Errorf("expected full replace, got nodes = %+v", got.Nodes)
	}
	if len(got.Edges) != 0 {
		t.Errorf("expected no edges after replace, got %+v", got.Edges)
	}
}

func TestSaveNilGraphErrors(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "graph.db")
	if err := Save(dbPath, nil); err == nil {
		t.Error("expected error saving nil graph, got nil")
	}
}
