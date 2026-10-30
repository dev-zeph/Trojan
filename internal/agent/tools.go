// Package agent is Trojan's white-box reviewer: a hypothesis loop that reasons
// over the project's local Code Property Graph (internal/graph) and emits
// concrete, testable hypotheses for the pen-test agent to prove.
//
// The design splits cleanly in two:
//
//   - The TOOL LAYER (this file). A Toolbox binds to a built *graph.Graph (plus,
//     optionally, a grey-box source reader and the project's memory) and
//     answers typed, name-addressed queries: list the entrypoints, follow a
//     data flow, summarise unguarded routes and client exposures, read a
//     handler, recall past results. It is pure and local, and fully
//     unit-tested offline (tools_test.go).
//
//   - The LOOP (loop.go). Each reasoning turn is one stateless call through a
//     Transport to the hosted whitebox-agent edge function, which holds the
//     model key, the system prompt and the tool definitions (none of which
//     ship in this binary: the repo is public). Tool calls the model requests
//     are executed HERE and their compact results sent back next turn.
//
// Privacy note: the graph is built and queried locally. Only the capped slices
// a tool returns (node keys, file:line anchors, short handler snippets) reach
// the model, and only during a run the user started.
package agent

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/dev-zeph/trojan/internal/graph"
	"github.com/dev-zeph/trojan/internal/greybox"
	"github.com/dev-zeph/trojan/internal/memory"
)

// Caps that keep every tool result small: a result is resent on every later
// turn of the run, so its size is paid for repeatedly.
const (
	maxToolResult   = 6000 // characters of JSON per tool result
	maxListItems    = 25   // nodes / paths per list result
	maxChunkCode    = 1500 // characters of source per read_source chunk
	maxSourceChunks = 3
	maxHistory      = 20
)

// SourceReader reads the project's own source by endpoint, symbol or query
// (implemented by *greybox.Source). Optional.
type SourceReader interface {
	ReadSource(req greybox.ReadSourceRequest) (greybox.ReadSourceResult, error)
}

// HistorySource is the project's security memory (implemented by
// *memory.Store). Optional.
type HistorySource interface {
	All() ([]memory.Event, error)
}

// Toolbox binds the tool layer to one built graph, plus the optional source
// reader and memory. Safe to construct per run.
type Toolbox struct {
	g       *graph.Graph
	source  SourceReader
	history HistorySource
	keys    map[string]bool
}

// NewToolbox wraps a built graph so the tools can query it.
func NewToolbox(g *graph.Graph) *Toolbox {
	keys := make(map[string]bool, len(g.Nodes))
	for _, n := range g.Nodes {
		if n.Key != "" {
			keys[n.Key] = true
		}
	}
	return &Toolbox{g: g, keys: keys}
}

// WithSource enables read_source. Without one it answers with a note.
func (t *Toolbox) WithSource(s SourceReader) *Toolbox { t.source = s; return t }

// WithHistory enables get_security_history.
func (t *Toolbox) WithHistory(h HistorySource) *Toolbox { t.history = h; return t }

// HasKey reports whether the graph contains a node with this stable key. The
// loop uses it to reject hypotheses that name nodes the model invented.
func (t *Toolbox) HasKey(key string) bool { return t.keys[key] }

// Graph returns the graph the toolbox queries.
func (t *Toolbox) Graph() *graph.Graph { return t.g }

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
	Key      string `json:"key,omitempty"`
	Guarded  bool   `json:"guarded,omitempty"`
	Client   bool   `json:"client_side,omitempty"`
}

func viewOf(n graph.Node) NodeView {
	return NodeView{
		ID:       n.ID,
		Key:      n.Key,
		Guarded:  n.Guarded,
		Client:   n.ClientSide,
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

// Dispatch runs a graph tool by name against the given JSON input and returns
// the result marshalled as a JSON string, ready to hand back as a tool_result.
// It is the single choke point the loop calls, and it is also directly
// unit-testable without any SDK. An unknown tool or malformed input is returned
// as an error rather than a panic, so a model mistake never takes down the run.
func (t *Toolbox) Dispatch(name string, input json.RawMessage) (string, error) {
	switch name {
	case toolListEntrypoints:
		return toJSON(capViews(t.ListEntrypoints()))

	case toolGetPIINodes:
		return toJSON(capViews(t.GetPIINodes()))

	case toolGetDataflow:
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

	case toolReadContext:
		var in struct {
			Symbol string `json:"symbol"`
		}
		if err := json.Unmarshal(input, &in); err != nil {
			return "", fmt.Errorf("read_context: bad input: %w", err)
		}
		return toJSON(capViews(t.ReadContext(in.Symbol)))

	case toolNeighbors:
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

	case toolUnguardedPaths:
		return toJSON(t.UnguardedPaths())

	case toolClientExposures:
		return toJSON(t.ClientExposures())

	case toolReadSource:
		var req greybox.ReadSourceRequest
		if err := json.Unmarshal(input, &req); err != nil {
			return "", fmt.Errorf("read_source: bad input: %w", err)
		}
		return t.ReadSource(req)

	case toolSecurityHistory:
		var in struct {
			NodeKey string `json:"node_key"`
			File    string `json:"file"`
		}
		if len(input) > 0 {
			if err := json.Unmarshal(input, &in); err != nil {
				return "", fmt.Errorf("get_security_history: bad input: %w", err)
			}
		}
		return t.SecurityHistory(in.NodeKey, in.File)

	default:
		return "", fmt.Errorf("unknown tool %q", name)
	}
}

// toJSON marshals a tool result, capped at maxToolResult characters. A cut
// result says so, so the model narrows its query instead of assuming it saw
// everything.
func toJSON(v any) (string, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	if len(b) > maxToolResult {
		return strings.ToValidUTF8(string(b[:maxToolResult]), "") + " ...[truncated: narrow the query]", nil
	}
	return string(b), nil
}

// capViews cuts a node list to maxListItems.
func capViews(v []NodeView) []NodeView {
	if len(v) > maxListItems {
		return v[:maxListItems]
	}
	return v
}
