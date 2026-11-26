package agent

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

var wbStripe = "sk_" + "live_" + "51HxQe2LkF9aZ0rT7wYbN3mVvC8dPq" // assembled at runtime; not real

type captureTransport struct{ got [][]Message }

func (c *captureTransport) Turn(_ context.Context, m []Message) (*TurnResult, error) {
	c.got = append(c.got, m)
	return &TurnResult{StopReason: "end_turn"}, nil
}

// The white-box agent's seed and source-chunk tool results are redacted
// before they reach the model; assistant turns pass through unchanged.
func TestWhiteboxWireRedactsSource(t *testing.T) {
	inner := &captureTransport{}
	tr := redactingTransport(inner)
	res, _ := json.Marshal(toolResultBlock{Type: "tool_result", ToolUseID: "t1", Content: "// src/pay.ts:9-11\nconst stripe = new Stripe(\"" + wbStripe + "\")\nexport default stripe\n"})
	asst := json.RawMessage(`{"type":"text","text":"checking"}`)
	msgs := []Message{
		userTextMessage("ORG CONTEXT: billing key " + wbStripe),
		{Role: "assistant", Content: []json.RawMessage{asst}},
		{Role: "user", Content: []json.RawMessage{res}},
	}
	if _, err := tr.Turn(context.Background(), msgs); err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(inner.got[0])
	if strings.Contains(string(b), wbStripe) {
		t.Fatal("raw key reached the white-box wire")
	}
	if !strings.Contains(string(b), "export default stripe") || string(inner.got[0][1].Content[0]) != string(asst) {
		t.Fatal("code or assistant turn changed")
	}
}
