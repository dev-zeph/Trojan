// Package graph builds Trojan's local Code Property Graph (CPG): a security-
// oriented model of a codebase where nodes are code elements (functions, the
// dangerous calls they make) and edges are relationships (who calls whom). On
// top of the call graph it tags taint sources (HTTP entrypoints), sinks
// (dangerous APIs), and PII, then reports the reachable source->sink paths an
// agent would reason about as attack hypotheses.
//
// This is layers 1-3 of docs/context-engine.md. It is the white-box counterpart
// to the black-box agentic-DAST engine, and the graph substrate the semantic
// index (internal/rag, layer 4) and the agent loop reason over.
//
// Everything here is pure Go — no CGO — to preserve the GOOS=… cross-compile the
// desktop app relies on. This demo slice parses Go via go/ast (the same approach
// internal/rag uses for Go chunking); the production build swaps in tree-sitter
// compiled to WASM (run via wazero) for language coverage, and persists the
// graph to SQLite + sqlite-vec instead of holding it in memory.
package graph

// NodeKind classifies a graph node.
type NodeKind string

const (
	// KindFunc is a function or method definition.
	KindFunc NodeKind = "func"
	// KindSink is a call to a dangerous API (SQL exec, os/exec, file write,
	// log write, …) — where tainted data does damage.
	KindSink NodeKind = "sink"
)

// EdgeKind classifies a graph edge.
type EdgeKind string

const (
	// EdgeCalls connects a function to a function it calls (same package).
	EdgeCalls EdgeKind = "calls"
	// EdgeContains connects a function to a sink that appears in its body.
	EdgeContains EdgeKind = "contains"
)

// Node is one element of the graph, anchored back to source so findings can
// cite file:line.
type Node struct {
	ID     int      `json:"id"`
	Kind   NodeKind `json:"kind"`
	Name   string   `json:"name"` // func: package-qualified symbol; sink: the callee, e.g. "exec.Command"
	File   string   `json:"file"`
	Line   int      `json:"line"`
	Source bool     `json:"source,omitempty"` // func reached from untrusted input (HTTP handler)
	PII    bool     `json:"pii,omitempty"`    // func touches data that looks like PII/PHI
	// SinkRule names why a sink node is dangerous (for report copy).
	SinkRule string `json:"sink_rule,omitempty"`
	// Severity is a coarse rank for sinks: "high" | "medium".
	Severity string `json:"severity,omitempty"`
}

// Edge is a directed relationship between two nodes.
type Edge struct {
	Src  int      `json:"src"`
	Dst  int      `json:"dst"`
	Kind EdgeKind `json:"kind"`
}

// Graph is the in-memory CPG. The production build persists this to SQLite; the
// demo keeps it in memory and can emit it as JSON.
type Graph struct {
	Nodes []Node `json:"nodes"`
	Edges []Edge `json:"edges"`

	// byFunc maps a package-qualified function name to its node ID, so calls
	// resolved by name during the build can be wired to the right node.
	byFunc map[string]int
}

// New returns an empty graph.
func New() *Graph {
	return &Graph{byFunc: make(map[string]int)}
}

// addNode appends a node, assigns it an ID, and returns that ID.
func (g *Graph) addNode(n Node) int {
	n.ID = len(g.Nodes)
	g.Nodes = append(g.Nodes, n)
	return n.ID
}

// addEdge appends a directed edge.
func (g *Graph) addEdge(src, dst int, kind EdgeKind) {
	g.Edges = append(g.Edges, Edge{Src: src, Dst: dst, Kind: kind})
}

// FuncNodes returns the IDs of all function nodes.
func (g *Graph) FuncNodes() []int {
	var ids []int
	for _, n := range g.Nodes {
		if n.Kind == KindFunc {
			ids = append(ids, n.ID)
		}
	}
	return ids
}
