package agent

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// Transport runs a single Claude turn: given the conversation so far, it returns
// Claude's next assistant message. The loop owns the conversation and the tool
// execution; the Transport only crosses the network boundary to reason. This
// interface is the seam the loop tests inject a scripted fake into.
type Transport interface {
	Turn(ctx context.Context, messages []Message) (*TurnResult, error)
}

// agenticURL is the Supabase edge function that holds the Anthropic API key,
// the system prompt, and the tool definitions, and runs one Claude turn per
// call (docs/agentic-dast.md §3.1 — orchestrate locally, reason in the cloud).
const agenticURL = "https://dtmocojzvgsswjdsrmqr.supabase.co/functions/v1/agentic-dast"

// EdgeTransport is the production Transport: it base64-wraps the conversation
// (so Cloudflare's WAF doesn't 403 on the attack payloads inside probe bodies —
// see _shared/body.ts) and POSTs it to the agentic-dast edge function.
type EdgeTransport struct {
	accessToken string
	url         string
	client      *http.Client
}

// NewEdgeTransport builds an EdgeTransport for a Pro user's access token.
func NewEdgeTransport(accessToken string) *EdgeTransport {
	return &EdgeTransport{
		accessToken: accessToken,
		url:         agenticURL,
		client:      &http.Client{Timeout: 90 * time.Second},
	}
}

// ErrRateLimited is returned when the daily agentic-run budget is exhausted.
var ErrRateLimited = fmt.Errorf("rate_limit_exceeded")

func (t *EdgeTransport) Turn(ctx context.Context, messages []Message) (*TurnResult, error) {
	inner, err := json.Marshal(map[string]any{"messages": messages})
	if err != nil {
		return nil, err
	}
	body, err := json.Marshal(map[string]string{"encoded": base64.StdEncoding.EncodeToString(inner)})
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+t.accessToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := t.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("agentic-dast request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusTooManyRequests {
		return nil, ErrRateLimited
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("agentic-dast turn failed (status %d)", resp.StatusCode)
	}

	var result TurnResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decoding agentic-dast turn: %w", err)
	}
	return &result, nil
}
