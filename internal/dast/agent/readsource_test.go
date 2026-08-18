package agent

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/dev-zeph/trojan/internal/greybox"
)

// fakeSource implements SourceReader, recording the request it received.
type fakeSource struct {
	got greybox.ReadSourceRequest
	res greybox.ReadSourceResult
}

func (f *fakeSource) ReadSource(req greybox.ReadSourceRequest) (greybox.ReadSourceResult, error) {
	f.got = req
	return f.res, nil
}

func TestRunReadSourceGreyBox(t *testing.T) {
	tb, _ := newTestbox(t, DefaultLimits(), http.NotFoundHandler())
	fs := &fakeSource{res: greybox.ReadSourceResult{
		Chunks:  []greybox.SourceChunk{{File: "app/api/users/[id]/route.ts", Line: 3, Symbol: "GET", Code: "db.query(\"...\" + id)"}},
		Summary: &greybox.StructuralSummary{RawQuery: true, HasAuthCheck: false},
	}}
	tb.SetSource(fs)

	tr := &fakeTransport{turns: []*TurnResult{
		turn("tool_use", toolUseBlock("r1", toolReadSource, greybox.ReadSourceRequest{
			Endpoint: &greybox.EndpointRef{Method: "GET", Path: "/api/users/5"},
		})),
		turn("tool_use", toolUseBlock("f1", toolFinish, map[string]any{"summary": "done"})),
	}}

	_, err := Run(context.Background(), tb, tr, RunOptions{Task: "go"})
	if err != nil {
		t.Fatal(err)
	}

	// The tool call reached the source reader with the right endpoint.
	if fs.got.Endpoint == nil || fs.got.Endpoint.Path != "/api/users/5" {
		t.Fatalf("source reader got %+v, want endpoint /api/users/5", fs.got)
	}
	// read_source must NOT consume the request budget (no target traffic).
	if _, reqs, _ := tb.Budget().Stats(); reqs != 0 {
		t.Errorf("read_source should cost 0 requests, got %d", reqs)
	}
	// The structural summary reached the model's tool_result.
	if len(tr.received) < 2 {
		t.Fatalf("expected a second turn")
	}
	last := tr.received[1]
	toolResult := string(last[len(last)-1].Content[0])
	if !strings.Contains(toolResult, "raw_query") || !strings.Contains(toolResult, "route.ts") {
		t.Errorf("tool_result missing grey-box context: %s", toolResult)
	}
}

func TestRunReadSourceBlackBoxFallback(t *testing.T) {
	tb, _ := newTestbox(t, DefaultLimits(), http.NotFoundHandler())
	// No source set — read_source must degrade to a note, not error.
	tr := &fakeTransport{turns: []*TurnResult{
		turn("tool_use", toolUseBlock("r1", toolReadSource, greybox.ReadSourceRequest{Symbol: "getUser"})),
		turn("tool_use", toolUseBlock("f1", toolFinish, map[string]any{"summary": "done"})),
	}}
	_, err := Run(context.Background(), tb, tr, RunOptions{Task: "go"})
	if err != nil {
		t.Fatal(err)
	}
	last := tr.received[1]
	toolResult := string(last[len(last)-1].Content[0])
	if !strings.Contains(toolResult, "black-box") {
		t.Errorf("expected black-box fallback note, got: %s", toolResult)
	}
}
