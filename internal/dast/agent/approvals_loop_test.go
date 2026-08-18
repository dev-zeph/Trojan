package agent

import (
	"context"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// postCountingBox spins up a server that counts POST hits and a Toolbox with HITL
// enabled, so a test can assert whether a gated action actually executed.
func postCountingBox(t *testing.T, approvals *Approvals) (*Toolbox, string, *int32) {
	t.Helper()
	var posts int32
	mux := http.NewServeMux()
	mux.HandleFunc("/orders/7/cancel", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			atomic.AddInt32(&posts, 1)
		}
		_, _ = w.Write([]byte(`{"ok":true}`))
	})
	tb, base := newTestbox(t, DefaultLimits(), mux) // TierSafeActive / EnvStaging → POST allowed by the floor
	tb.SetApprovals(approvals)
	return tb, base, &posts
}

func containsOutcome(msgs [][]Message, needle string) bool {
	for _, conv := range msgs {
		for _, m := range conv {
			for _, blk := range m.Content {
				if strings.Contains(string(blk), needle) {
					return true
				}
			}
		}
	}
	return false
}

func TestApprovalGrantedExecutesAction(t *testing.T) {
	ap := NewApprovals(2 * time.Second)
	tb, base, posts := postCountingBox(t, ap)
	// The gated POST becomes approval #1 — pre-load the operator's approval.
	ap.Decide(ApprovalDecision{ID: 1, Approve: true})

	tr := &fakeTransport{turns: []*TurnResult{
		turn("tool_use", toolUseBlock("p1", toolHTTPProbe, ProbeRequest{Method: "POST", URL: base + "/orders/7/cancel", Body: "{}"})),
		turn("tool_use", toolUseBlock("f1", toolFinish, map[string]any{"summary": "done"})),
	}}

	var reqEvt, resEvt int
	res, err := Run(context.Background(), tb, tr, RunOptions{Task: "go", OnEvent: func(e Event) {
		switch e.Type {
		case EventApprovalRequest:
			reqEvt++
		case EventApprovalResolved:
			resEvt++
		}
	}})
	if err != nil {
		t.Fatal(err)
	}
	if atomic.LoadInt32(posts) != 1 {
		t.Errorf("approved POST should have executed exactly once, got %d", *posts)
	}
	if reqEvt != 1 || resEvt != 1 {
		t.Errorf("want 1 request + 1 resolved event, got %d/%d", reqEvt, resEvt)
	}
	if !containsOutcome(tr.received, "APPROVAL #1 GRANTED") {
		t.Error("granted-approval outcome was not fed back to the agent")
	}
	if res.EndedBy != EventFinish {
		t.Errorf("EndedBy = %q, want finish", res.EndedBy)
	}
}

func TestApprovalDeniedDoesNotExecute(t *testing.T) {
	ap := NewApprovals(2 * time.Second)
	tb, base, posts := postCountingBox(t, ap)
	ap.Decide(ApprovalDecision{ID: 1, Approve: false, Note: "out of scope"})

	tr := &fakeTransport{turns: []*TurnResult{
		turn("tool_use", toolUseBlock("p1", toolHTTPProbe, ProbeRequest{Method: "POST", URL: base + "/orders/7/cancel", Body: "{}"})),
		turn("tool_use", toolUseBlock("f1", toolFinish, map[string]any{"summary": "done"})),
	}}

	if _, err := Run(context.Background(), tb, tr, RunOptions{Task: "go"}); err != nil {
		t.Fatal(err)
	}
	if atomic.LoadInt32(posts) != 0 {
		t.Errorf("denied POST must NOT execute, but it ran %d time(s)", *posts)
	}
	if !containsOutcome(tr.received, "APPROVAL #1 DENIED") {
		t.Error("denial outcome was not fed back to the agent")
	}
	// The PENDING sentinel must have reached the agent, not an error.
	if !containsOutcome(tr.received, "PENDING_APPROVAL#1") {
		t.Error("agent was not handed a PENDING_APPROVAL for the gated action")
	}
}

func TestApprovalTimeoutAutoDenies(t *testing.T) {
	ap := NewApprovals(40 * time.Millisecond) // no decision will arrive
	tb, base, posts := postCountingBox(t, ap)

	tr := &fakeTransport{turns: []*TurnResult{
		turn("tool_use", toolUseBlock("p1", toolHTTPProbe, ProbeRequest{Method: "POST", URL: base + "/orders/7/cancel", Body: "{}"})),
		turn("tool_use", toolUseBlock("f1", toolFinish, map[string]any{"summary": "done"})),
	}}

	res, err := Run(context.Background(), tb, tr, RunOptions{Task: "go"})
	if err != nil {
		t.Fatal(err)
	}
	if atomic.LoadInt32(posts) != 0 {
		t.Errorf("timed-out approval must default to safe (not executed), ran %d time(s)", *posts)
	}
	if !containsOutcome(tr.received, "AUTO-DENIED") {
		t.Error("timeout should have produced an auto-deny outcome")
	}
	if res.EndedBy != EventFinish {
		t.Errorf("EndedBy = %q, want finish", res.EndedBy)
	}
}

func TestApprovalAutoActionNotGated(t *testing.T) {
	ap := NewApprovals(2 * time.Second)
	tb, base, _ := postCountingBox(t, ap)
	// A GET is read-only/in-scope → executes immediately, no approval queued.
	tr := &fakeTransport{turns: []*TurnResult{
		turn("tool_use", toolUseBlock("g1", toolHTTPProbe, ProbeRequest{Method: "GET", URL: base + "/orders/7/cancel"})),
		turn("tool_use", toolUseBlock("f1", toolFinish, map[string]any{"summary": "done"})),
	}}
	var reqEvt int
	if _, err := Run(context.Background(), tb, tr, RunOptions{Task: "go", OnEvent: func(e Event) {
		if e.Type == EventApprovalRequest {
			reqEvt++
		}
	}}); err != nil {
		t.Fatal(err)
	}
	if reqEvt != 0 {
		t.Errorf("a GET must not be gated, but %d approval(s) were requested", reqEvt)
	}
	if _, reqs, _ := tb.Budget().Stats(); reqs != 1 {
		t.Errorf("the GET should have executed once, got %d requests", reqs)
	}
}

func TestApprovalDenylistBlocks(t *testing.T) {
	ap := NewApprovals(2 * time.Second)
	tb, base, _ := postCountingBox(t, ap)
	tb.Envelope().SetRoE(RoE{EndpointDenylist: []string{"/orders/*"}})

	tr := &fakeTransport{turns: []*TurnResult{
		turn("tool_use", toolUseBlock("g1", toolHTTPProbe, ProbeRequest{Method: "GET", URL: base + "/orders/7/cancel"})),
		turn("tool_use", toolUseBlock("f1", toolFinish, map[string]any{"summary": "done"})),
	}}
	if _, err := Run(context.Background(), tb, tr, RunOptions{Task: "go"}); err != nil {
		t.Fatal(err)
	}
	if !containsOutcome(tr.received, "blocked by rules of engagement") {
		t.Error("denylisted GET should have come back as a block tool error")
	}
	if _, reqs, _ := tb.Budget().Stats(); reqs != 0 {
		t.Errorf("a blocked action must not spend the request budget, got %d", reqs)
	}
}
