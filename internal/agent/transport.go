package agent

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"
)

// Transport runs a single reasoning turn: given the conversation so far, it
// returns the model's next assistant message. The loop owns the conversation
// and executes every tool locally; the Transport only crosses the network to
// reason. Tests inject a scripted fake here, so they make no network calls.
type Transport interface {
	Turn(ctx context.Context, messages []Message) (*TurnResult, error)
}

// whiteboxURL is the Supabase edge function that holds the model key, the
// system prompt and the tool definitions, and runs one turn per call. None of
// that lives in this binary: the repo is public and the prompt is not.
const whiteboxURL = "https://dtmocojzvgsswjdsrmqr.supabase.co/functions/v1/whitebox-agent"

// ErrRateLimited is returned when the daily AI budget is exhausted (429).
var ErrRateLimited = errors.New("rate_limit_exceeded")

// ErrInsufficientTokens is returned when the user's Trojan Token balance cannot
// cover the run (402). Distinct from ErrRateLimited: this needs a top-up, not a
// wait.
var ErrInsufficientTokens = errors.New("insufficient_tokens")

// ErrUnauthorized is returned when the access token is missing or rejected.
var ErrUnauthorized = errors.New("unauthorized")

// EdgeTransport is the production Transport. It base64-wraps the conversation
// so Cloudflare's WAF does not 403 on the code snippets and attack strings
// inside tool results (see _shared/body.ts), authenticates with the user's
// Bearer token, and latches the server-minted run id.
type EdgeTransport struct {
	accessToken string
	url         string
	client      *http.Client

	// runID is empty until the first turn returns one. Not mutex-guarded: the
	// loop is strictly sequential and a transport is never shared across runs.
	runID string
}

// NewEdgeTransport builds an EdgeTransport for a signed-in user's token.
func NewEdgeTransport(accessToken string) *EdgeTransport {
	return &EdgeTransport{
		accessToken: accessToken,
		url:         whiteboxURL,
		client:      &http.Client{Timeout: 90 * time.Second},
	}
}

// RunID is the server-minted id of this run ("" before the first turn).
func (t *EdgeTransport) RunID() string { return t.runID }

func (t *EdgeTransport) Turn(ctx context.Context, messages []Message) (*TurnResult, error) {
	payload := map[string]any{"messages": messages}
	if t.runID != "" {
		payload["runId"] = t.runID
	}
	inner, err := json.Marshal(payload)
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
		return nil, fmt.Errorf("whitebox-agent request failed: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusUnauthorized:
		return nil, ErrUnauthorized
	case http.StatusPaymentRequired:
		return nil, ErrInsufficientTokens
	case http.StatusTooManyRequests:
		return nil, ErrRateLimited
	default:
		return nil, fmt.Errorf("whitebox-agent turn failed (status %d)", resp.StatusCode)
	}

	var result TurnResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decoding whitebox-agent turn: %w", err)
	}
	if t.runID == "" && result.RunID != "" {
		t.runID = result.RunID
	}
	return &result, nil
}
