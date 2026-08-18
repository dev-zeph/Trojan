package agent

import (
	"fmt"
	"strings"
	"sync"
)

// AttackGraph is the run's single backing state model (docs §9.3): the agent
// reasons over it and the UI renders it. Today it's a live coverage/vulnerability
// map — endpoints discovered, which are being tested, which proved vulnerable,
// with the grey-box handler behind each. It becomes a true kill-chain graph for
// free once the chaining tool (§6.5 #5) adds cross-node edges; the shape doesn't
// change, only how densely edges get populated.
//
// Nodes and edges are streamed to the UI as incremental deltas, so a mid-run
// viewer catches up from the replay buffer and then tails live.

// NodeType classifies a graph node.
type NodeType string

const (
	NodeEndpoint   NodeType = "endpoint"
	NodeFinding    NodeType = "finding"
	NodeCredential NodeType = "credential"
	NodeData       NodeType = "data"
)

// NodeStatus is the node's place in the test lifecycle. Compass Area-2 encoding:
// untested = gray, testing = yellow (live), vulnerable = red, chained =
// highlighted. safe is an explicit "tested, nothing found" so the map shows
// coverage, not just hits.
type NodeStatus string

const (
	StatusUntested   NodeStatus = "untested"
	StatusTesting    NodeStatus = "testing"
	StatusSafe       NodeStatus = "safe"
	StatusVulnerable NodeStatus = "vulnerable"
	StatusChained    NodeStatus = "chained"
)

// statusRank orders statuses so a node never regresses (a proved-vulnerable node
// can't fall back to "testing" on a later probe).
func statusRank(s NodeStatus) int {
	switch s {
	case StatusUntested:
		return 0
	case StatusTesting:
		return 1
	case StatusSafe:
		return 2
	case StatusVulnerable:
		return 3
	case StatusChained:
		return 4
	}
	return 0
}

// HandlerRef is the grey-box source location behind a node — the "source
// predicted" half of the source↔runtime proof pair (§6.6, §9.2).
type HandlerRef struct {
	File   string `json:"file"`
	Line   int    `json:"line"`
	Symbol string `json:"symbol,omitempty"`
}

// GraphNode is one asset/step in the attack graph.
type GraphNode struct {
	ID       string      `json:"id"`
	Type     NodeType    `json:"type"`
	Label    string      `json:"label"`
	Method   string      `json:"method,omitempty"` // for endpoints
	Status   NodeStatus  `json:"status"`
	Severity string      `json:"severity,omitempty"`
	Attack   string      `json:"attack,omitempty"` // attack class / MITRE technique
	Handler  *HandlerRef `json:"handler,omitempty"`
	Evidence string      `json:"evidence,omitempty"`
}

// EdgeKind classifies how two nodes relate.
type EdgeKind string

const (
	EdgeChain    EdgeKind = "chain"    // one step enables the next (kill chain)
	EdgeDataflow EdgeKind = "dataflow" // data moves from one node to another
	EdgeTrust    EdgeKind = "trust"    // a trust relationship between nodes
)

// GraphEdge connects two nodes.
type GraphEdge struct {
	From      string   `json:"from"`
	To        string   `json:"to"`
	Kind      EdgeKind `json:"kind"`
	Confirmed bool     `json:"confirmed"`
	Rationale string   `json:"rationale,omitempty"`
}

// AttackGraph holds the nodes and edges. Safe for concurrent use.
type AttackGraph struct {
	mu    sync.Mutex
	nodes map[string]*GraphNode
	order []string // node insertion order, for deterministic snapshots
	edges []GraphEdge
	edgeK map[string]bool // dedup key set for edges
}

// NewAttackGraph returns an empty graph.
func NewAttackGraph() *AttackGraph {
	return &AttackGraph{nodes: map[string]*GraphNode{}, edgeK: map[string]bool{}}
}

// EndpointID is the canonical node id for a live endpoint.
func EndpointID(method, path string) string {
	m := strings.ToUpper(strings.TrimSpace(method))
	if m == "" {
		m = "ANY"
	}
	return "ep:" + m + " " + path
}

// UpsertEndpoint adds an endpoint node (untested) if absent. Returns the node
// and whether anything changed (so the caller can decide to emit a delta).
func (g *AttackGraph) UpsertEndpoint(method, path string) (GraphNode, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	id := EndpointID(method, path)
	if _, ok := g.nodes[id]; ok {
		return *g.nodes[id], false
	}
	n := &GraphNode{ID: id, Type: NodeEndpoint, Label: path, Method: strings.ToUpper(method), Status: StatusUntested}
	g.nodes[id] = n
	g.order = append(g.order, id)
	return *n, true
}

// SetStatus raises an endpoint node's status (never lowers it). Returns the node
// and whether it changed. A missing node is created as an endpoint first.
func (g *AttackGraph) SetStatus(id string, s NodeStatus) (GraphNode, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	n, ok := g.nodes[id]
	if !ok {
		return GraphNode{}, false
	}
	if statusRank(s) <= statusRank(n.Status) {
		return *n, false
	}
	n.Status = s
	return *n, true
}

// AttachHandler records the grey-box source location on a node (idempotent-ish:
// only emits a change when the handler actually differs).
func (g *AttackGraph) AttachHandler(id string, h HandlerRef) (GraphNode, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	n, ok := g.nodes[id]
	if !ok {
		return GraphNode{}, false
	}
	if n.Handler != nil && *n.Handler == h {
		return *n, false
	}
	hc := h
	n.Handler = &hc
	return *n, true
}

// MarkVulnerable raises a node to vulnerable and annotates it. Used when a
// finding is confirmed against an endpoint.
func (g *AttackGraph) MarkVulnerable(id, severity, attack, evidence string) (GraphNode, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	n, ok := g.nodes[id]
	if !ok {
		return GraphNode{}, false
	}
	changed := false
	if statusRank(StatusVulnerable) > statusRank(n.Status) {
		n.Status = StatusVulnerable
		changed = true
	}
	if severity != "" && n.Severity != severity {
		n.Severity = severity
		changed = true
	}
	if attack != "" && n.Attack != attack {
		n.Attack = attack
		changed = true
	}
	if evidence != "" && n.Evidence != evidence {
		n.Evidence = evidence
		changed = true
	}
	return *n, changed
}

// AddFinding adds a finding node keyed by a stable id.
func (g *AttackGraph) AddFinding(id, label, severity, attack, evidence string, handler *HandlerRef) (GraphNode, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	nid := "find:" + id
	if _, ok := g.nodes[nid]; ok {
		return *g.nodes[nid], false
	}
	n := &GraphNode{
		ID: nid, Type: NodeFinding, Label: label, Status: StatusVulnerable,
		Severity: severity, Attack: attack, Evidence: evidence, Handler: handler,
	}
	g.nodes[nid] = n
	g.order = append(g.order, nid)
	return *n, true
}

// AddCredentialNode adds a credential/data node captured during chaining (§6.5
// #5 / §9). Keyed by id so repeats are no-ops.
func (g *AttackGraph) AddCredentialNode(id, label string, nodeType NodeType) (GraphNode, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	nid := "cred:" + id
	if _, ok := g.nodes[nid]; ok {
		return *g.nodes[nid], false
	}
	n := &GraphNode{ID: nid, Type: nodeType, Label: label, Status: StatusChained}
	g.nodes[nid] = n
	g.order = append(g.order, nid)
	return *n, true
}

// EndpointNodeByPath returns the id of the first endpoint node whose path matches,
// so chaining edges can connect real nodes. ok is false when no endpoint matches.
func (g *AttackGraph) EndpointNodeByPath(path string) (string, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, id := range g.order {
		n := g.nodes[id]
		if n.Type == NodeEndpoint && n.Label == path {
			return id, true
		}
	}
	return "", false
}

// AddEdge adds a deduplicated edge. Returns whether it was new.
func (g *AttackGraph) AddEdge(from, to string, kind EdgeKind, confirmed bool, rationale string) (GraphEdge, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	e := GraphEdge{From: from, To: to, Kind: kind, Confirmed: confirmed, Rationale: rationale}
	key := fmt.Sprintf("%s|%s|%s", from, to, kind)
	if g.edgeK[key] {
		return e, false
	}
	g.edgeK[key] = true
	g.edges = append(g.edges, e)
	return e, true
}

// MarkVulnerableByPath raises every endpoint node whose path (Label) matches to
// vulnerable and annotates it. Findings reference a URL, not a node id, so this
// matches by path. Returns the nodes that changed. If nothing matched, it
// creates an any-method endpoint node for the path and marks that.
func (g *AttackGraph) MarkVulnerableByPath(path, severity, attack, evidence string) []GraphNode {
	g.mu.Lock()
	matched := false
	var changed []GraphNode
	for _, id := range g.order {
		n := g.nodes[id]
		if n.Type != NodeEndpoint || n.Label != path {
			continue
		}
		matched = true
		if g.raiseVulnLocked(n, severity, attack, evidence) {
			changed = append(changed, *n)
		}
	}
	g.mu.Unlock()

	if !matched && path != "" {
		g.UpsertEndpoint("", path)
		if n, ch := g.MarkVulnerable(EndpointID("", path), severity, attack, evidence); ch {
			changed = append(changed, n)
		}
	}
	return changed
}

// AttachHandlerByPath attaches a grey-box handler to every endpoint node whose
// path matches. Returns the changed nodes.
func (g *AttackGraph) AttachHandlerByPath(path string, h HandlerRef) []GraphNode {
	g.mu.Lock()
	defer g.mu.Unlock()
	var changed []GraphNode
	for _, id := range g.order {
		n := g.nodes[id]
		if n.Type != NodeEndpoint || n.Label != path {
			continue
		}
		if n.Handler != nil && *n.Handler == h {
			continue
		}
		hc := h
		n.Handler = &hc
		changed = append(changed, *n)
	}
	return changed
}

// raiseVulnLocked applies the vulnerable status + annotations to a node in place;
// caller holds the lock. Returns whether anything changed.
func (g *AttackGraph) raiseVulnLocked(n *GraphNode, severity, attack, evidence string) bool {
	changed := false
	if statusRank(StatusVulnerable) > statusRank(n.Status) {
		n.Status = StatusVulnerable
		changed = true
	}
	if severity != "" && n.Severity != severity {
		n.Severity, changed = severity, true
	}
	if attack != "" && n.Attack != attack {
		n.Attack, changed = attack, true
	}
	if evidence != "" && n.Evidence != evidence {
		n.Evidence, changed = evidence, true
	}
	return changed
}

// Snapshot returns a deterministic copy of the whole graph (for the initial push
// to a viewer that attached before any deltas).
func (g *AttackGraph) Snapshot() ([]GraphNode, []GraphEdge) {
	g.mu.Lock()
	defer g.mu.Unlock()
	nodes := make([]GraphNode, 0, len(g.order))
	for _, id := range g.order {
		nodes = append(nodes, *g.nodes[id])
	}
	edges := make([]GraphEdge, len(g.edges))
	copy(edges, g.edges)
	return nodes, edges
}

// Counts summarizes the graph for the run counters.
func (g *AttackGraph) Counts() (endpoints, tested, vulnerable int) {
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, n := range g.nodes {
		if n.Type != NodeEndpoint {
			continue
		}
		endpoints++
		if n.Status != StatusUntested {
			tested++
		}
		if n.Status == StatusVulnerable || n.Status == StatusChained {
			vulnerable++
		}
	}
	return
}
