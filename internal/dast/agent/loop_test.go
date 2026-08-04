package agent

import (
	"context"
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"testing"
)

// fakeTransport scripts a fixed sequence of assistant turns and records the
// messages it was handed on each call (to assert conversation accumulation and
// verbatim thinking-block replay). Once the script is exhausted it returns a
// clean end_turn so a mis-scripted test can't loop forever.
type fakeTransport struct {
	turns    []*TurnResult
	calls    int
	received [][]Message
}

func (f *fakeTransport) Turn(_ context.Context, msgs []Message) (*TurnResult, error) {
	snapshot := make([]Message, len(msgs))
	copy(snapshot, msgs)
	f.received = append(f.received, snapshot)

	if f.calls >= len(f.turns) {
		f.calls++
		return &TurnResult{StopReason: "end_turn"}, nil
	}
	t := f.turns[f.calls]
	f.calls++
	return t, nil
}

func textBlock(s string) json.RawMessage {
	j, _ := json.Marshal(map[string]any{"type": "text", "text": s})
	return j
}
func thinkingBlock(s string) json.RawMessage {
	j, _ := json.Marshal(map[string]any{"type": "thinking", "thinking": s})
	return j
}
func toolUseBlock(id, name string, input any) json.RawMessage {
	j, _ := json.Marshal(map[string]any{"type": "tool_use", "id": id, "name": name, "input": input})
	return j
}
func turn(stop string, blocks ...json.RawMessage) *TurnResult {
	return &TurnResult{Content: blocks, StopReason: stop, Usage: Usage{OutputTokens: 10}}
}

func TestRunFinishesOnFinishTool(t *testing.T) {
	tb, _ := newTestbox(t, DefaultLimits(), http.NotFoundHandler())
	tr := &fakeTransport{turns: []*TurnResult{
		turn("tool_use", textBlock("Let me look at the map."), toolUseBlock("t1", toolGetCrawlMap, map[string]any{})),
		turn("tool_use", toolUseBlock("t2", toolFinish, map[string]any{"summary": "nothing exploitable"})),
	}}

	res, err := Run(context.Background(), tb, tr, RunOptions{Task: "pen-test the app"})
	if err != nil {
		t.Fatal(err)
	}
	if res.EndedBy != EventFinish {
		t.Errorf("EndedBy = %q, want finish", res.EndedBy)
	}
	if res.Summary != "nothing exploitable" {
		t.Errorf("Summary = %q", res.Summary)
	}
	if res.Steps != 2 {
		t.Errorf("Steps = %d, want 2", res.Steps)
	}
}

func TestRunHTTPProbeAndFinding(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("secret data"))
	})
	tb, base := newTestbox(t, DefaultLimits(), mux)

	tr := &fakeTransport{turns: []*TurnResult{
		turn("tool_use", toolUseBlock("p1", toolHTTPProbe, ProbeRequest{Method: "GET", URL: base + "/"})),
		turn("tool_use",
			toolUseBlock("n1", toolNoteFinding, Candidate{Title: "Exposed data", Severity: "medium", URL: base + "/"}),
			toolUseBlock("f1", toolFinish, map[string]any{"summary": "1 finding"}),
		),
	}}

	res, err := Run(context.Background(), tb, tr, RunOptions{Task: "go"})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 || res.Findings[0].Title != "Exposed data" {
		t.Errorf("findings = %+v, want 1 'Exposed data'", res.Findings)
	}
	if _, reqs, _ := tb.Budget().Stats(); reqs != 1 {
		t.Errorf("expected exactly 1 probe request, got %d", reqs)
	}
	// The tool_result fed back to the model must carry the probe's response.
	if len(tr.received) < 2 {
		t.Fatalf("expected 2 turns, got %d", len(tr.received))
	}
	last := tr.received[1]
	toolResultMsg := last[len(last)-1]
	if toolResultMsg.Role != "user" || !strings.Contains(string(toolResultMsg.Content[0]), "secret data") {
		t.Errorf("tool_result did not carry the probe response: %s", toolResultMsg.Content[0])
	}
}

func TestRunStopsOnStepBudget(t *testing.T) {
	lim := DefaultLimits()
	lim.MaxSteps = 2
	tb, _ := newTestbox(t, lim, http.NotFoundHandler())

	// Never calls finish — always asks for the crawl map again.
	loopTurn := turn("tool_use", toolUseBlock("t", toolGetCrawlMap, map[string]any{}))
	tr := &fakeTransport{turns: []*TurnResult{loopTurn, loopTurn, loopTurn, loopTurn}}

	res, err := Run(context.Background(), tb, tr, RunOptions{Task: "go"})
	if err != nil {
		t.Fatal(err)
	}
	if res.EndedBy != EventStopped {
		t.Errorf("EndedBy = %q, want stopped", res.EndedBy)
	}
	if res.StopReason != StopStepBudget {
		t.Errorf("StopReason = %q, want %q", res.StopReason, StopStepBudget)
	}
	if res.Steps != 2 {
		t.Errorf("Steps = %d, want 2", res.Steps)
	}
}

func TestRunStopsOnTokenBudget(t *testing.T) {
	tb, _ := newTestbox(t, DefaultLimits(), http.NotFoundHandler())
	tr := &fakeTransport{turns: []*TurnResult{
		{Content: []json.RawMessage{toolUseBlock("t", toolGetCrawlMap, map[string]any{})},
			StopReason: "tool_use", Usage: Usage{InputTokens: 5000, OutputTokens: 5000}},
	}}

	res, err := Run(context.Background(), tb, tr, RunOptions{Task: "go", MaxRunTokens: 1000})
	if err != nil {
		t.Fatal(err)
	}
	if res.EndedBy != EventStopped || res.StopReason != StopTokenBudget {
		t.Errorf("EndedBy=%q StopReason=%q; want stopped / %q", res.EndedBy, res.StopReason, StopTokenBudget)
	}
	if res.Usage.Total() != 10000 {
		t.Errorf("cumulative usage = %d, want 10000", res.Usage.Total())
	}
}

func TestRunEndsCleanlyOnEndTurn(t *testing.T) {
	tb, _ := newTestbox(t, DefaultLimits(), http.NotFoundHandler())
	// Agent replies with text only and stops asking for tools.
	tr := &fakeTransport{turns: []*TurnResult{
		turn("end_turn", textBlock("I could not reach the target.")),
	}}

	res, err := Run(context.Background(), tb, tr, RunOptions{Task: "go"})
	if err != nil {
		t.Fatal(err)
	}
	if res.EndedBy != EventFinish {
		t.Errorf("EndedBy = %q, want finish (clean end)", res.EndedBy)
	}
	if res.Steps != 1 {
		t.Errorf("Steps = %d, want 1", res.Steps)
	}
}

func TestRunReplaysThinkingVerbatim(t *testing.T) {
	tb, _ := newTestbox(t, DefaultLimits(), http.NotFoundHandler())
	think := thinkingBlock("the login form is POST, I'll stay read-only")
	tr := &fakeTransport{turns: []*TurnResult{
		turn("tool_use", think, toolUseBlock("t1", toolGetCrawlMap, map[string]any{})),
		turn("tool_use", toolUseBlock("f1", toolFinish, map[string]any{"summary": "done"})),
	}}

	if _, err := Run(context.Background(), tb, tr, RunOptions{Task: "go"}); err != nil {
		t.Fatal(err)
	}
	// The second turn's messages must contain the assistant turn with the
	// thinking block replayed byte-for-byte.
	second := tr.received[1]
	found := false
	for _, m := range second {
		if m.Role != "assistant" {
			continue
		}
		for _, blk := range m.Content {
			if string(blk) == string(think) {
				found = true
			}
		}
	}
	if !found {
		t.Error("thinking block was not replayed verbatim on the next turn")
	}
}

func TestRunEmitsEvents(t *testing.T) {
	tb, _ := newTestbox(t, DefaultLimits(), http.NotFoundHandler())
	tr := &fakeTransport{turns: []*TurnResult{
		turn("tool_use",
			textBlock("hypothesis"),
			toolUseBlock("n1", toolNoteFinding, Candidate{Title: "X", Severity: "low"}),
			toolUseBlock("f1", toolFinish, map[string]any{"summary": "s"}),
		),
	}}

	var seen []EventType
	_, err := Run(context.Background(), tb, tr, RunOptions{Task: "go", OnEvent: func(e Event) {
		seen = append(seen, e.Type)
	}})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []EventType{EventStep, EventText, EventToolUse, EventFinding, EventFinish} {
		if !slices.Contains(seen, want) {
			t.Errorf("missing event %q in %v", want, seen)
		}
	}
}

func TestRunSafeModeRejectionBecomesToolError(t *testing.T) {
	tb, _ := newTestbox(t, DefaultLimits(), http.NotFoundHandler())
	// Off-host probe — safe-mode rejects it; the loop should feed the error
	// back as a tool_result (is_error) rather than crashing, then finish.
	tr := &fakeTransport{turns: []*TurnResult{
		turn("tool_use", toolUseBlock("p1", toolHTTPProbe, ProbeRequest{Method: "GET", URL: "https://evil.example.com/"})),
		turn("tool_use", toolUseBlock("f1", toolFinish, map[string]any{"summary": "blocked"})),
	}}

	res, err := Run(context.Background(), tb, tr, RunOptions{Task: "go"})
	if err != nil {
		t.Fatal(err)
	}
	if res.EndedBy != EventFinish {
		t.Errorf("EndedBy = %q, want finish", res.EndedBy)
	}
	// The error tool_result must have been fed back on turn 2.
	last := tr.received[1]
	trMsg := last[len(last)-1]
	var blk toolResultBlock
	if err := json.Unmarshal(trMsg.Content[0], &blk); err != nil {
		t.Fatal(err)
	}
	if !blk.IsError || !strings.Contains(blk.Content, "off-host") {
		t.Errorf("expected an off-host is_error tool_result, got %+v", blk)
	}
}

