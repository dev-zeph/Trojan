package agent

import "testing"

func TestAttackGraphEndpointLifecycle(t *testing.T) {
	g := NewAttackGraph()

	// Discover.
	n, changed := g.UpsertEndpoint("GET", "/api/orders/{id}")
	if !changed || n.Status != StatusUntested {
		t.Fatalf("new endpoint should be untested/changed, got %+v changed=%v", n, changed)
	}
	// Re-discovering the same endpoint is a no-op.
	if _, changed := g.UpsertEndpoint("get", "/api/orders/{id}"); changed {
		t.Errorf("re-upsert should not change")
	}

	id := EndpointID("GET", "/api/orders/{id}")
	// untested -> testing.
	if _, changed := g.SetStatus(id, StatusTesting); !changed {
		t.Errorf("untested->testing should change")
	}
	// testing -> vulnerable.
	if n, changed := g.MarkVulnerable(id, "high", "IDOR", "leaked adjacent order"); !changed || n.Status != StatusVulnerable {
		t.Errorf("should mark vulnerable, got %+v changed=%v", n, changed)
	}
	// vulnerable must NOT regress to testing.
	if _, changed := g.SetStatus(id, StatusTesting); changed {
		t.Errorf("vulnerable must not regress to testing")
	}
}

func TestAttackGraphHandlerAndCounts(t *testing.T) {
	g := NewAttackGraph()
	g.UpsertEndpoint("GET", "/a")
	g.UpsertEndpoint("POST", "/b")
	g.UpsertEndpoint("GET", "/c")

	idA := EndpointID("GET", "/a")
	g.SetStatus(idA, StatusTesting)
	g.MarkVulnerable(idA, "high", "SQLi", "error-based")

	g.SetStatus(EndpointID("POST", "/b"), StatusSafe)
	// /c stays untested.

	// Attach a grey-box handler.
	h := HandlerRef{File: "app/api/a/route.ts", Line: 12, Symbol: "GET"}
	if _, changed := g.AttachHandler(idA, h); !changed {
		t.Errorf("attach handler should change")
	}
	if _, changed := g.AttachHandler(idA, h); changed {
		t.Errorf("re-attaching identical handler should be a no-op")
	}

	endpoints, tested, vuln := g.Counts()
	if endpoints != 3 || tested != 2 || vuln != 1 {
		t.Errorf("counts = (%d endpoints, %d tested, %d vuln), want (3,2,1)", endpoints, tested, vuln)
	}
}

func TestAttackGraphFindingAndEdges(t *testing.T) {
	g := NewAttackGraph()
	g.UpsertEndpoint("GET", "/api/orders/{id}")
	epID := EndpointID("GET", "/api/orders/{id}")

	fn, changed := g.AddFinding("cand-1", "IDOR on orders", "high", "IDOR", "mallory read alice's order",
		&HandlerRef{File: "app/api/orders/[id]/route.ts", Line: 12, Symbol: "GET"})
	if !changed || fn.Type != NodeFinding || fn.Status != StatusVulnerable {
		t.Fatalf("finding node wrong: %+v", fn)
	}
	// Duplicate finding id is a no-op.
	if _, changed := g.AddFinding("cand-1", "x", "low", "", "", nil); changed {
		t.Errorf("duplicate finding should not change")
	}

	// Edge finding -> endpoint.
	if _, isNew := g.AddEdge(fn.ID, epID, EdgeChain, true, "finding confirmed on this endpoint"); !isNew {
		t.Errorf("edge should be new")
	}
	if _, isNew := g.AddEdge(fn.ID, epID, EdgeChain, true, "dup"); isNew {
		t.Errorf("duplicate edge should be deduped")
	}

	nodes, edges := g.Snapshot()
	if len(nodes) != 2 || len(edges) != 1 {
		t.Fatalf("snapshot = %d nodes, %d edges, want 2/1", len(nodes), len(edges))
	}
	// Snapshot order is insertion order: endpoint first, finding second.
	if nodes[0].ID != epID || nodes[1].ID != fn.ID {
		t.Errorf("snapshot order wrong: %s, %s", nodes[0].ID, nodes[1].ID)
	}
}
