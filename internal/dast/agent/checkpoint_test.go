package agent

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// isolateHome points checkpoint storage at a temp dir so tests never read or
// write the developer's real ~/.trojan/runs.
func isolateHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home) // windows
	return home
}

func TestCheckpointRoundTrip(t *testing.T) {
	isolateHome(t)

	cp := &Checkpoint{
		RunID:     "11111111-2222-3333-4444-555555555555",
		TargetURL: "https://example.test",
		Task:      "pen-test it",
		Messages:  []Message{userTextMessage("hello")},
		Usage:     Usage{InputTokens: 100, OutputTokens: 20},
		Findings:  []Candidate{{Title: "SQLi", Severity: "high"}},
		Facts:     []Fact{{Kind: "credential", Summary: "admin token", Value: "abc"}},
		Steps:     3,
		Requests:  9,
		Elapsed:   42 * time.Second,
		Resumable: true,
	}
	if err := SaveCheckpoint(cp); err != nil {
		t.Fatal(err)
	}

	got, err := LoadCheckpoint(cp.RunID)
	if err != nil {
		t.Fatal(err)
	}
	if got.TargetURL != cp.TargetURL || got.Task != cp.Task {
		t.Errorf("run shape lost: %+v", got)
	}
	if len(got.Messages) != 1 || len(got.Findings) != 1 || len(got.Facts) != 1 {
		t.Errorf("live state lost: %d msgs, %d findings, %d facts",
			len(got.Messages), len(got.Findings), len(got.Facts))
	}
	if got.Facts[0].Value != "abc" {
		t.Errorf("fact value lost, kill-chain memory would not survive resume")
	}
	if got.Steps != 3 || got.Requests != 9 || got.Elapsed != 42*time.Second {
		t.Errorf("budget lost: steps=%d requests=%d elapsed=%s", got.Steps, got.Requests, got.Elapsed)
	}
	if !got.Resumable {
		t.Error("Resumable lost")
	}
}

// A checkpoint holds Identity auth headers and captured response bodies, so the
// file must not be group/world readable.
func TestCheckpointFileIsPrivate(t *testing.T) {
	home := isolateHome(t)
	cp := &Checkpoint{RunID: "aaaa", TargetURL: "https://x.test"}
	if err := SaveCheckpoint(cp); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(home, ".trojan", "runs", "aaaa.json"))
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("checkpoint mode = %o, want 600", perm)
	}
}

func TestCheckpointRejectsVersionMismatch(t *testing.T) {
	home := isolateHome(t)
	dir := filepath.Join(home, ".trojan", "runs")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	// A future/no version must be refused, not half-restored: a partially
	// rehydrated agent would silently re-probe or lose established facts.
	body := []byte(`{"version": 999, "run_id": "future"}`)
	if err := os.WriteFile(filepath.Join(dir, "future.json"), body, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadCheckpoint("future"); !errors.Is(err, ErrCheckpointVersion) {
		t.Errorf("err = %v, want ErrCheckpointVersion", err)
	}
}

// Run ids are server-minted UUIDs, but this is where a hostile one would become
// an arbitrary file write.
func TestCheckpointRejectsPathTraversal(t *testing.T) {
	isolateHome(t)
	for _, bad := range []string{"", "../escape", "a/b", `a\b`, "..", "x/../../y"} {
		if _, err := checkpointPath(bad); err == nil {
			t.Errorf("checkpointPath(%q) accepted a traversal-capable id", bad)
		}
	}
}

func TestListCheckpointsSkipsCorruptFiles(t *testing.T) {
	home := isolateHome(t)
	if err := SaveCheckpoint(&Checkpoint{RunID: "good", TargetURL: "https://good.test", Resumable: true}); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(home, ".trojan", "runs")
	if err := os.WriteFile(filepath.Join(dir, "broken.json"), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	// One unreadable file must not hide every other resumable run.
	list, err := ListCheckpoints()
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].RunID != "good" {
		t.Errorf("list = %+v, want just the good run", list)
	}
}

func TestGraphRestoreRebuildsEdgeDedup(t *testing.T) {
	g := NewAttackGraph()
	g.Restore(
		[]GraphNode{{ID: "n1", Label: "a"}, {ID: "n2", Label: "b"}},
		[]GraphEdge{{From: "n1", To: "n2", Kind: EdgeKind("leads_to")}},
	)
	nodes, edges := g.Snapshot()
	if len(nodes) != 2 || len(edges) != 1 {
		t.Fatalf("restore lost data: %d nodes, %d edges", len(nodes), len(edges))
	}
	// The restored dedup set must use AddEdge's key format, or a resumed run
	// would duplicate every edge it already had.
	if _, added := g.AddEdge("n1", "n2", EdgeKind("leads_to"), false, ""); added {
		t.Error("AddEdge re-added an edge the checkpoint already contained")
	}
}

func TestBudgetRestorePreservesConsumedCaps(t *testing.T) {
	lim := DefaultLimits()
	b := NewBudget(lim, nil)
	b.Restore(lim.MaxSteps-1, 5, 30*time.Second)

	steps, requests, elapsed := b.Stats()
	if steps != lim.MaxSteps-1 || requests != 5 {
		t.Errorf("counters lost: steps=%d requests=%d", steps, requests)
	}
	if elapsed < 30*time.Second {
		t.Errorf("elapsed = %s, want >= 30s", elapsed)
	}
	// One step left, then the cap must trip -- a resumed run does not get a
	// fresh budget to burn.
	if err := b.BeginStep(); err != nil {
		t.Fatalf("expected one remaining step, got %v", err)
	}
	if err := b.BeginStep(); err == nil {
		t.Error("resumed run got a fresh step budget")
	}
}

// failingTransport returns a fixed error on the Nth call, to exercise the
// out-of-tokens path.
type failingTransport struct {
	turns   []*TurnResult
	failAt  int
	err     error
	calls   int
	lastMsg []Message
}

func (f *failingTransport) Turn(_ context.Context, msgs []Message) (*TurnResult, error) {
	f.lastMsg = append([]Message(nil), msgs...)
	f.calls++
	if f.calls == f.failAt {
		return nil, f.err
	}
	if f.calls-1 < len(f.turns) {
		return f.turns[f.calls-1], nil
	}
	return &TurnResult{StopReason: "end_turn"}, nil
}

func TestRunStopsResumablyWhenTokensRunOut(t *testing.T) {
	isolateHome(t)
	tb, _ := newTestbox(t, DefaultLimits(), http.NotFoundHandler())

	tr := &failingTransport{
		turns: []*TurnResult{
			// Must actually request a tool, or the loop treats the turn as the
			// agent choosing to stop and finishes before the second call.
			{Content: []json.RawMessage{
				textBlock("thinking about it"),
				toolUseBlock("t1", toolGetCrawlMap, map[string]any{}),
			}, StopReason: "tool_use", Usage: Usage{OutputTokens: 10}, RunID: "run-abc"},
		},
		failAt: 2,
		err:    ErrInsufficientTokens,
	}

	cp := &Checkpoint{TargetURL: "https://example.test", Task: "pen-test"}
	res, err := Run(context.Background(), tb, tr, RunOptions{Task: "pen-test", Checkpoint: cp})
	if err != nil {
		t.Fatalf("running out of tokens should pause, not error: %v", err)
	}
	if res.StopReason != StopInsufficientTokens {
		t.Errorf("StopReason = %q, want %q", res.StopReason, StopInsufficientTokens)
	}

	saved, err := LoadCheckpoint("run-abc")
	if err != nil {
		t.Fatalf("no checkpoint written, the run would be lost: %v", err)
	}
	if !saved.Resumable {
		t.Error("out-of-tokens checkpoint must be resumable")
	}
	if len(saved.Messages) == 0 {
		t.Error("conversation not saved, resume would restart from scratch")
	}
}

func TestBudgetCapEndsRunNonResumably(t *testing.T) {
	isolateHome(t)
	lim := DefaultLimits()
	lim.MaxSteps = 1
	tb, _ := newTestbox(t, lim, http.NotFoundHandler())

	tr := &fakeTransport{turns: []*TurnResult{
		{Content: []json.RawMessage{
			toolUseBlock("t1", toolGetCrawlMap, map[string]any{}),
		}, StopReason: "tool_use", Usage: Usage{OutputTokens: 5}, RunID: "run-cap"},
	}}

	cp := &Checkpoint{TargetURL: "https://example.test", Task: "pen-test"}
	if _, err := Run(context.Background(), tb, tr, RunOptions{Task: "pen-test", Checkpoint: cp}); err != nil {
		t.Fatal(err)
	}

	saved, err := LoadCheckpoint("run-cap")
	if err != nil {
		t.Fatal(err)
	}
	// A tripped step cap is a real end: resuming would hand back the same
	// exhausted budget, so the UI must offer "new run", not "continue".
	if saved.Resumable {
		t.Error("a budget-capped run must not be marked resumable")
	}
}

func TestResumeContinuesFromSavedConversation(t *testing.T) {
	isolateHome(t)
	tb, _ := newTestbox(t, DefaultLimits(), http.NotFoundHandler())

	prior := []Message{
		userTextMessage("pen-test"),
		{Role: "assistant", Content: []json.RawMessage{textBlock("I found a login form")}},
	}
	cp := &Checkpoint{
		RunID: "run-resume", TargetURL: "https://example.test", Task: "pen-test",
		Messages: prior, Usage: Usage{InputTokens: 500}, Resumable: true,
	}

	tr := &fakeTransport{turns: []*TurnResult{
		turn("tool_use", toolUseBlock("t1", toolFinish, map[string]any{"summary": "done"})),
	}}
	res, err := Run(context.Background(), tb, tr, RunOptions{Task: "pen-test", Checkpoint: cp})
	if err != nil {
		t.Fatal(err)
	}

	// The transport must have been handed the PRIOR conversation, not a fresh
	// one -- otherwise the agent re-discovers everything and re-bills for it.
	if len(tr.received) == 0 {
		t.Fatal("transport never called")
	}
	first := tr.received[0]
	if len(first) != len(prior) {
		t.Fatalf("resumed with %d messages, want the saved %d", len(first), len(prior))
	}
	// Cumulative usage must carry over so a run-level token cap stays honest.
	if res.Usage.InputTokens < 500 {
		t.Errorf("usage reset on resume: %+v", res.Usage)
	}
}
