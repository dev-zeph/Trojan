package agent

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/dev-zeph/trojan/internal/graph"
)

// scriptedTransport replays a fixed list of turns, one per Turn call, so loop
// tests make no network calls and spend no tokens. An out-of-turns call errors
// (overrun) unless errAt is set, which forces that error on a given turn.
type scriptedTransport struct {
	turns  []*TurnResult
	errAt  int   // 1-based turn index that returns err; 0 = never
	err    error // the error to return at errAt
	calls  int
	lastMs []Message
}

func (s *scriptedTransport) Turn(_ context.Context, m []Message) (*TurnResult, error) {
	s.calls++
	s.lastMs = m
	if s.errAt == s.calls {
		return nil, s.err
	}
	if s.calls > len(s.turns) {
		return &TurnResult{StopReason: "end_turn"}, nil
	}
	return s.turns[s.calls-1], nil
}

// block builds one content block for a scripted assistant turn.
func block(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}

func textTurn(text, stop string) *TurnResult {
	return &TurnResult{
		Content:    []json.RawMessage{block(map[string]string{"type": "text", "text": text})},
		StopReason: stop,
		Usage:      Usage{InputTokens: 100, OutputTokens: 20},
	}
}

func toolTurn(name string, input any, runID string) *TurnResult {
	return &TurnResult{
		Content: []json.RawMessage{block(map[string]any{
			"type": "tool_use", "id": "tu_" + name, "name": name, "input": input,
		})},
		StopReason: "tool_use",
		Usage:      Usage{InputTokens: 100, OutputTokens: 30},
		RunID:      runID,
	}
}

// vibeToolbox builds a toolbox over a graph with the vibeapp order POST node.
func vibeToolbox(t *testing.T) *Toolbox {
	t.Helper()
	g := graph.New()
	g.Nodes = []graph.Node{
		{ID: 0, Kind: graph.KindFunc, Key: "app/api/orders/route.ts#POST", Name: "POST", File: "app/api/orders/route.ts", Line: 3, Source: true},
		{ID: 1, Kind: graph.KindDataStore, Key: "datastore:orders", Name: "orders", File: "supabase/migrations/0001_init.sql", Line: 1},
	}
	g.Edges = []graph.Edge{{Src: 0, Dst: 1, Kind: graph.EdgeWrites}}
	return NewToolbox(g)
}

func TestRun_EmitThenFinish(t *testing.T) {
	tb := vibeToolbox(t)
	hyp := map[string]any{
		"title":             "Public order write",
		"node_keys":         []string{"app/api/orders/route.ts#POST", "datastore:orders"},
		"class":             "missing-auth",
		"method":            "post",
		"path":              "/api/orders",
		"expected_evidence": "an unauthenticated POST returns 200 and a row appears in orders",
		"confidence":        "high",
		"impact":            "Anyone on the internet can create orders without signing in.",
	}
	tr := &scriptedTransport{turns: []*TurnResult{
		toolTurn(toolUnguardedPaths, map[string]any{}, "run-123"),
		toolTurn(toolEmitHypothesis, hyp, ""),
		toolTurn(toolFinish, map[string]string{"summary": "Checked the order surface; one missing-auth write."}, ""),
	}}
	res, err := Run(context.Background(), tb, tr, "seed", Options{})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.StopReason != StopFinished {
		t.Fatalf("stop reason = %q, want finished", res.StopReason)
	}
	if res.RunID != "run-123" {
		t.Fatalf("run id = %q, want run-123", res.RunID)
	}
	if len(res.Hypotheses) != 1 {
		t.Fatalf("want 1 hypothesis, got %d", len(res.Hypotheses))
	}
	h := res.Hypotheses[0]
	if h.ID != "H1" || h.Method != "POST" || h.Class != "missing-auth" {
		t.Fatalf("hypothesis normalised wrong: %+v", h)
	}
	if res.Summary == "" {
		t.Fatal("want a summary from finish")
	}
	if res.Usage.Total() == 0 {
		t.Fatal("usage not accumulated")
	}
}

func TestRun_ToolRoundTrip(t *testing.T) {
	tb := vibeToolbox(t)
	tr := &scriptedTransport{turns: []*TurnResult{
		toolTurn(toolUnguardedPaths, map[string]any{}, "r1"),
		textTurn("done", "end_turn"),
	}}
	if _, err := Run(context.Background(), tb, tr, "seed", Options{}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	// After the tool turn the loop must send a user message carrying a
	// tool_result that contains the executed graph query's output.
	last := tr.lastMs[len(tr.lastMs)-1]
	if last.Role != "user" {
		t.Fatalf("want a trailing user turn, got role %q", last.Role)
	}
	var peek blockPeek
	_ = json.Unmarshal(last.Content[0], &peek)
	if peek.Type != "tool_result" || !strings.Contains(peek.Text+string(last.Content[0]), "datastore:orders") {
		t.Fatalf("tool_result did not carry the graph output: %s", last.Content[0])
	}
}

func TestRun_TurnBudget(t *testing.T) {
	tb := vibeToolbox(t)
	// Every turn asks for a tool and never finishes.
	tr := &scriptedTransport{turns: []*TurnResult{
		toolTurn(toolUnguardedPaths, map[string]any{}, "r1"),
		toolTurn(toolUnguardedPaths, map[string]any{}, ""),
		toolTurn(toolUnguardedPaths, map[string]any{}, ""),
		toolTurn(toolUnguardedPaths, map[string]any{}, ""),
	}}
	res, err := Run(context.Background(), tb, tr, "seed", Options{MaxTurns: 2})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.StopReason != StopTurnBudget || res.Turns != 2 {
		t.Fatalf("want turn-budget stop at 2 turns, got %q at %d", res.StopReason, res.Turns)
	}
}

func TestRun_TokenBudget(t *testing.T) {
	tb := vibeToolbox(t)
	tr := &scriptedTransport{turns: []*TurnResult{
		toolTurn(toolUnguardedPaths, map[string]any{}, "r1"), // 130 tokens
		toolTurn(toolUnguardedPaths, map[string]any{}, ""),   // crosses 200
	}}
	res, err := Run(context.Background(), tb, tr, "seed", Options{MaxTokens: 200})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.StopReason != StopTokenBudget {
		t.Fatalf("want token-budget stop, got %q", res.StopReason)
	}
}

func TestRun_InsufficientTokens(t *testing.T) {
	tb := vibeToolbox(t)
	tr := &scriptedTransport{errAt: 1, err: ErrInsufficientTokens}
	res, err := Run(context.Background(), tb, tr, "seed", Options{})
	if err == nil || !strings.Contains(err.Error(), "insufficient_tokens") {
		t.Fatalf("want insufficient_tokens error, got %v", err)
	}
	if res.StopReason != StopInsufficientTokens {
		t.Fatalf("want out-of-tokens stop, got %q", res.StopReason)
	}
}

func TestEmit_RejectsUnknownKey(t *testing.T) {
	tb := vibeToolbox(t)
	bad := map[string]any{
		"node_keys": []string{"app/api/ghost/route.ts#POST"}, "class": "missing-auth",
		"path": "/api/ghost", "expected_evidence": "x", "confidence": "high",
	}
	tr := &scriptedTransport{turns: []*TurnResult{
		toolTurn(toolEmitHypothesis, bad, "r1"),
		toolTurn(toolFinish, map[string]string{"summary": "s"}, ""),
	}}
	res, err := Run(context.Background(), tb, tr, "seed", Options{})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(res.Hypotheses) != 0 {
		t.Fatalf("invented-key hypothesis must be rejected, got %+v", res.Hypotheses)
	}
	// The model must have been told why, as a tool error.
	last := tr.lastMs[len(tr.lastMs)-1]
	if !strings.Contains(string(last.Content[0]), "unknown node key") {
		t.Fatalf("want an unknown-key error back to the model, got %s", last.Content[0])
	}
}

func TestEmit_Dedup(t *testing.T) {
	tb := vibeToolbox(t)
	h := map[string]any{
		"node_keys": []string{"datastore:orders"}, "class": "missing-auth",
		"method": "POST", "path": "/api/orders", "expected_evidence": "x", "confidence": "high",
	}
	tr := &scriptedTransport{turns: []*TurnResult{
		toolTurn(toolEmitHypothesis, h, "r1"),
		toolTurn(toolEmitHypothesis, h, ""),
		toolTurn(toolFinish, map[string]string{"summary": "s"}, ""),
	}}
	res, _ := Run(context.Background(), tb, tr, "seed", Options{})
	if len(res.Hypotheses) != 1 {
		t.Fatalf("duplicate hypothesis must be dropped, got %d", len(res.Hypotheses))
	}
}
