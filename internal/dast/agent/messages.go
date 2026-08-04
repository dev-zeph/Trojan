package agent

import "encoding/json"

// Message is one turn in the Claude conversation the loop maintains. Content is
// kept as raw blocks so assistant turns — including thinking blocks, which
// Claude requires replayed byte-for-byte on the next turn — round-trip through
// the Go loop and the edge function untouched.
type Message struct {
	Role    string            `json:"role"`
	Content []json.RawMessage `json:"content"`
}

// TurnResult is what the edge function returns for one Claude turn: the raw
// content blocks, the stop reason, and token usage.
type TurnResult struct {
	Content    []json.RawMessage `json:"content"`
	StopReason string            `json:"stop_reason"`
	Usage      Usage             `json:"usage"`
}

// Usage mirrors the Anthropic usage object; the loop accumulates it across turns
// to enforce a cumulative token ceiling and to report run cost.
type Usage struct {
	InputTokens              int `json:"input_tokens"`
	OutputTokens             int `json:"output_tokens"`
	CacheReadInputTokens     int `json:"cache_read_input_tokens"`
	CacheCreationInputTokens int `json:"cache_creation_input_tokens"`
}

// Total is the billable token count for a turn (all input tiers + output).
func (u Usage) Total() int {
	return u.InputTokens + u.OutputTokens + u.CacheReadInputTokens + u.CacheCreationInputTokens
}

func (u *Usage) add(o Usage) {
	u.InputTokens += o.InputTokens
	u.OutputTokens += o.OutputTokens
	u.CacheReadInputTokens += o.CacheReadInputTokens
	u.CacheCreationInputTokens += o.CacheCreationInputTokens
}

// blockPeek is the minimal view of a content block the loop needs to route it:
// text for progress, tool_use for dispatch. Everything else (thinking,
// signatures) is ignored here but preserved in the raw Message.Content.
type blockPeek struct {
	Type  string          `json:"type"`
	ID    string          `json:"id"`    // tool_use id
	Name  string          `json:"name"`  // tool_use name
	Input json.RawMessage `json:"input"` // tool_use input
	Text  string          `json:"text"`  // text block
}

// toolResultBlock is a tool_result content block sent back in a user turn.
type toolResultBlock struct {
	Type      string `json:"type"`
	ToolUseID string `json:"tool_use_id"`
	Content   string `json:"content"`
	IsError   bool   `json:"is_error,omitempty"`
}

func userTextMessage(text string) Message {
	block, _ := json.Marshal(map[string]string{"type": "text", "text": text})
	return Message{Role: "user", Content: []json.RawMessage{block}}
}

func toolResultMessage(blocks []toolResultBlock) Message {
	raw := make([]json.RawMessage, len(blocks))
	for i, b := range blocks {
		b.Type = "tool_result"
		j, _ := json.Marshal(b)
		raw[i] = j
	}
	return Message{Role: "user", Content: raw}
}
