// Package agent exposes Trojan's local Code Property Graph (internal/graph) to
// an AI model as a small set of pentester-style tools, and drives a
// hypothesis-driven reasoning loop on top of them.
//
// The design splits cleanly in two:
//
//   - The TOOL LAYER (this file). A Toolbox binds to a built *graph.Graph and
//     answers typed queries a model can call, the way a pen-tester queries their
//     notes: list the entrypoints, follow a data flow, look up a symbol, find
//     the PII, walk a node's neighbours. Each tool has a typed Go signature, a
//     JSON schema for tool-calling, and a name-addressed Dispatch. This layer is
//     pure and deterministic (no network, no SDK), so it is fully unit-tested
//     offline (tools_test.go).
//
//   - The LOOP (loop.go). It hands those tools to Claude via the Anthropic Go
//     SDK and asks the model to form one grounded attack hypothesis. The live
//     call is gated behind ANTHROPIC_API_KEY, so nothing here needs a key (or
//     spends money) to build or to test.
//
// Privacy note: the graph and these tools run entirely locally. Only the minimal
// slices a tool returns (symbol names, file:line anchors, a severity) ever reach
// the model, and only when the loop is actually run with a key. Nothing is
// persisted on Trojan servers.
package agent

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/dev-zeph/trojan/internal/graph"
)

// Toolbox binds the tool layer to one built graph. It holds no other state, so
// it is safe to construct per run and cheap to reuse across tool calls.
type Toolbox struct {
	g *graph.Graph
}

// NewToolbox wraps a built graph so the tools can query it.
func NewToolbox(g *graph.Graph) *Toolbox {
	return &Toolbox{g: g}
}

// NodeView is the model-facing projection of a graph node: the same fields plus
// a precomputed "file:line" Location, which is what the model cites in a
// finding. Keeping this separate from graph.Node means the tool contract does
// not shift if the graph adds internal fields.
type NodeView struct {
	ID       int    `json:"id"`
	Kind     string `json:"kind"`
	Name     string `json:"name"`
	File     string `json:"file"`
	Line     int    `json:"line"`
	Location string `json:"location"`
	Source   bool   `json:"source"`
	PII      bool   `json:"pii"`
	SinkRule string `json:"sink_rule,omitempty"`
	Severity string `json:"severity,omitempty"`
}

func viewOf(n graph.Node) NodeView {
	return NodeView{
		ID:       n.ID,
		Kind:     string(n.Kind),
		Name:     n.Name,
		File:     n.File,
		Line:     n.Line,
		Location: fmt.Sprintf("%s:%d", n.File, n.Line),
		Source:   n.Source,
		PII:      n.PII,
		SinkRule: n.SinkRule,
		Severity: n.Severity,
	}
}

func viewsOf(ns []graph.Node) []NodeView {
	out := make([]NodeView, 0, len(ns))
	for _, n := range ns {
		out = append(out, viewOf(n))
	}
	return out
}

// node returns a node by ID, guarding the index the model supplies (a model can
// invent an ID, and an out-of-range slice access would panic the whole loop).
func (t *Toolbox) node(id int) (graph.Node, bool) {
	if id < 0 || id >= len(t.g.Nodes) {
		return graph.Node{}, false
	}
	return t.g.Nodes[id], true
}

// ListEntrypoints returns the source function nodes: the untrusted entrypoints
// (HTTP handlers) tainted input arrives through. These are where an attack
// begins, so this is normally the model's first call.
func (t *Toolbox) ListEntrypoints() []NodeView {
	var out []NodeView
	for _, n := range t.g.Nodes {
		if n.Kind == graph.KindFunc && n.Source {
			out = append(out, viewOf(n))
		}
	}
	return out
}

// DataflowResult is the answer to get_dataflow: whether tainted data can reach
// the sink from the source, and, if so, the concrete function chain proving it.
type DataflowResult struct {
	Found    bool       `json:"found"`
	Source   NodeView   `json:"source"`
	Sink     NodeView   `json:"sink"`
	Via      []NodeView `json:"via"`
	Severity string     `json:"severity,omitempty"`
	TouchPII bool       `json:"touch_pii"`
	// Note explains a not-found result so the model does not read it as "no
	// answer" and retry forever.
	Note string `json:"note,omitempty"`
}

// GetDataflow returns the call chain from sourceID to sinkID, if one exists, by
// selecting the matching route out of graph.Paths(). sourceID must be a source
// function node and sinkID a sink node; a route is "found" only when the graph
// actually connects them.
func (t *Toolbox) GetDataflow(sourceID, sinkID int) (DataflowResult, error) {
	src, ok := t.node(sourceID)
	if !ok {
		return DataflowResult{}, fmt.Errorf("no node with id %d (source)", sourceID)
	}
	sink, ok := t.node(sinkID)
	if !ok {
		return DataflowResult{}, fmt.Errorf("no node with id %d (sink)", sinkID)
	}

	for _, p := range t.g.Paths() {
		if p.Source.ID == sourceID && p.Sink.ID == sinkID {
			return DataflowResult{
				Found:    true,
				Source:   viewOf(p.Source),
				Sink:     viewOf(p.Sink),
				Via:      viewsOf(p.Via),
				Severity: p.Severity,
				TouchPII: p.TouchPII,
			}, nil
		}
	}

	return DataflowResult{
		Found:  false,
		Source: viewOf(src),
		Sink:   viewOf(sink),
		Note:   "no call chain connects this source to this sink in the graph",
	}, nil
}

// ReadContext returns the node(s) whose name matches symbol, each with its
// file:line, so the model can resolve a name it saw in one result to concrete
// locations. Matching is exact first; if nothing matches exactly it falls back
// to a case-insensitive substring match, so a bare "login" finds
// "api.loginHandler".
func (t *Toolbox) ReadContext(symbol string) []NodeView {
	symbol = strings.TrimSpace(symbol)
	if symbol == "" {
		return nil
	}

	var exact, partial []graph.Node
	lower := strings.ToLower(symbol)
	for _, n := range t.g.Nodes {
		switch {
		case n.Name == symbol:
			exact = append(exact, n)
		case strings.Contains(strings.ToLower(n.Name), lower):
			partial = append(partial, n)
		}
	}
	if len(exact) > 0 {
		return viewsOf(exact)
	}
	if len(partial) > 0 {
		return viewsOf(partial)
	}
	return nil
}

// GetPIINodes returns the function nodes flagged as touching PII/PHI. A source
// to sink path that also crosses one of these is materially worse, so the model
// uses this to weigh severity.
func (t *Toolbox) GetPIINodes() []NodeView {
	var out []NodeView
	for _, n := range t.g.Nodes {
		if n.PII {
			out = append(out, viewOf(n))
		}
	}
	return out
}

// Neighbors returns the nodes directly reachable from nodeID along outgoing
// edges. edgeKind filters by relationship: "calls" (functions this function
// calls), "contains" (sinks in this function's body), or "" / "any" for both.
func (t *Toolbox) Neighbors(nodeID int, edgeKind string) ([]NodeView, error) {
	if _, ok := t.node(nodeID); !ok {
		return nil, fmt.Errorf("no node with id %d", nodeID)
	}
	kind := strings.ToLower(strings.TrimSpace(edgeKind))
	switch kind {
	case "", "any", "calls", "contains":
	default:
		return nil, fmt.Errorf("unknown edge kind %q (want calls, contains, or any)", edgeKind)
	}

	// Deduplicate destinations while preserving graph order.
	seen := make(map[int]bool)
	var out []NodeView
	for _, e := range t.g.Edges {
		if e.Src != nodeID {
			continue
		}
		if kind != "" && kind != "any" && string(e.Kind) != kind {
			continue
		}
		if seen[e.Dst] {
			continue
		}
		seen[e.Dst] = true
		if n, ok := t.node(e.Dst); ok {
			out = append(out, viewOf(n))
		}
	}
	return out, nil
}

// ---- Tool-calling contract ------------------------------------------------

// ToolSpec is one tool advertised to the model: its name, a description the
// model reads to decide when to call it, and the JSON schema of its input. It is
// deliberately SDK-agnostic (plain maps), so the tool layer carries no
// dependency on the Anthropic SDK; the loop translates these into SDK tool
// params.
type ToolSpec struct {
	Name        string
	Description string
	Properties  map[string]any
	Required    []string
}

// ToolSpecs returns the JSON-schema definitions for the five graph tools, in a
// stable order. emit_finding (the loop's terminal tool) is defined by the loop,
// not here, because it is a control-flow concern rather than a graph query.
func ToolSpecs() []ToolSpec {
	return []ToolSpec{
		{
			Name:        "list_entrypoints",
			Description: "List the untrusted entrypoints (HTTP handler functions) where attacker-controlled input enters the code. Start here. Returns node ids you pass to the other tools.",
			Properties:  map[string]any{},
		},
		{
			Name:        "get_dataflow",
			Description: "Return the call chain from a source entrypoint to a dangerous sink, if the graph connects them. Use it to confirm tainted input can actually reach the sink before forming a hypothesis.",
			Properties: map[string]any{
				"source_id": map[string]any{"type": "integer", "description": "node id of a source entrypoint (from list_entrypoints)"},
				"sink_id":   map[string]any{"type": "integer", "description": "node id of a sink (from neighbors with edge_kind=contains)"},
			},
			Required: []string{"source_id", "sink_id"},
		},
		{
			Name:        "read_context",
			Description: "Look up graph node(s) by symbol name and get each one's file:line. Use it to resolve a function or callee name you saw in another result to a concrete location.",
			Properties: map[string]any{
				"symbol": map[string]any{"type": "string", "description": "a function or callee name, exact or partial (e.g. 'loginHandler' or 'login')"},
			},
			Required: []string{"symbol"},
		},
		{
			Name:        "get_pii_nodes",
			Description: "List the functions flagged as touching PII/PHI (passwords, tokens, emails, medical data). A data flow that crosses one of these is more severe.",
			Properties:  map[string]any{},
		},
		{
			Name:        "neighbors",
			Description: "List the nodes directly reachable from a node along outgoing edges. edge_kind 'calls' gives functions it calls, 'contains' gives sinks in its body, 'any' gives both. Use 'contains' to find the sinks inside an entrypoint.",
			Properties: map[string]any{
				"node_id":   map[string]any{"type": "integer", "description": "the node id to expand"},
				"edge_kind": map[string]any{"type": "string", "enum": []string{"calls", "contains", "any"}, "description": "which relationship to follow"},
			},
			Required: []string{"node_id"},
		},
	}
}

// Dispatch runs a graph tool by name against the given JSON input and returns
// the result marshalled as a JSON string, ready to hand back as a tool_result.
// It is the single choke point the loop calls, and it is also directly
// unit-testable without any SDK. An unknown tool or malformed input is returned
// as an error rather than a panic, so a model mistake never takes down the run.
func (t *Toolbox) Dispatch(name string, input json.RawMessage) (string, error) {
	switch name {
	case "list_entrypoints":
		return toJSON(t.ListEntrypoints())

	case "get_pii_nodes":
		return toJSON(t.GetPIINodes())

	case "get_dataflow":
		var in struct {
			SourceID int `json:"source_id"`
			SinkID   int `json:"sink_id"`
		}
		if err := json.Unmarshal(input, &in); err != nil {
			return "", fmt.Errorf("get_dataflow: bad input: %w", err)
		}
		res, err := t.GetDataflow(in.SourceID, in.SinkID)
		if err != nil {
			return "", err
		}
		return toJSON(res)

	case "read_context":
		var in struct {
			Symbol string `json:"symbol"`
		}
		if err := json.Unmarshal(input, &in); err != nil {
			return "", fmt.Errorf("read_context: bad input: %w", err)
		}
		return toJSON(t.ReadContext(in.Symbol))

	case "neighbors":
		var in struct {
			NodeID   int    `json:"node_id"`
			EdgeKind string `json:"edge_kind"`
		}
		if err := json.Unmarshal(input, &in); err != nil {
			return "", fmt.Errorf("neighbors: bad input: %w", err)
		}
		res, err := t.Neighbors(in.NodeID, in.EdgeKind)
		if err != nil {
			return "", err
		}
		return toJSON(res)

	default:
		return "", fmt.Errorf("unknown tool %q", name)
	}
}

// toolNames returns the graph tool names, sorted, for validation and tests.
func toolNames() []string {
	specs := ToolSpecs()
	names := make([]string, 0, len(specs))
	for _, s := range specs {
		names = append(names, s.Name)
	}
	sort.Strings(names)
	return names
}

func toJSON(v any) (string, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	return string(b), nil
}
