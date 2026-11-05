package agent

import "encoding/json"

// Wire types shared with the whitebox-agent edge function. They mirror
// internal/dast/agent's: content blocks stay json.RawMessage end to end so an
// assistant turn (thinking blocks and their signatures included) is replayed
// to the server byte for byte on the next call.

// Message is one turn of the conversation the loop owns and resends each turn.
type Message struct {
	Role    string            `json:"role"`
	Content []json.RawMessage `json:"content"`
}

// TurnResult is what the edge function returns for one reasoning turn.
type TurnResult struct {
	Content    []json.RawMessage `json:"content"`
	StopReason string            `json:"stop_reason"`
	Usage      Usage             `json:"usage"`
	// RunID is minted server-side on the first turn; the transport echoes it on
	// every later turn so the run is debited once and its usage rolls up.
	RunID string `json:"runId"`
	// TokenBalance is the user's Trojan Token balance after this turn (billing
	// units, not LLM tokens).
	TokenBalance int `json:"tokenBalance"`
}

// Usage is the LLM token usage of one turn, as reported by the server.
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

// blockPeek is the minimal view of a content block the loop needs to route it.
// Everything else (thinking, signatures) is preserved in the raw content.
type blockPeek struct {
	Type  string          `json:"type"`
	ID    string          `json:"id"`
	Name  string          `json:"name"`
	Input json.RawMessage `json:"input"`
	Text  string          `json:"text"`
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

func toolResultsMessage(results []toolResultBlock) Message {
	content := make([]json.RawMessage, 0, len(results))
	for _, r := range results {
		r.Type = "tool_result"
		j, _ := json.Marshal(r)
		content = append(content, j)
	}
	return Message{Role: "user", Content: content}
}
