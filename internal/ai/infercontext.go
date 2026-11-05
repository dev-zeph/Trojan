package ai

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/dev-zeph/trojan/internal/fingerprint"
	"github.com/dev-zeph/trojan/internal/orgcontext"
)

// inferContextURL is a var so tests can point it at an httptest server.
var inferContextURL = "https://dtmocojzvgsswjdsrmqr.supabase.co/functions/v1/infer-context"

// OverrideInferContextURL is a test-only hook; it returns a func that restores
// the real URL.
func OverrideInferContextURL(url string) (restore func()) {
	orig := inferContextURL
	inferContextURL = url
	return func() { inferContextURL = orig }
}

// ContextMismatch is a place where the founder's description and the code
// disagree. The founder is asked which is right; nothing is picked silently.
type ContextMismatch struct {
	Said     string `json:"said"`
	Found    string `json:"found"`
	Question string `json:"question"`
}

// InferContextResult is the draft returned by the infer-context edge function.
type InferContextResult struct {
	Context    orgcontext.OrgContext `json:"context"`
	Questions  []string              `json:"questions"`
	Mismatches []ContextMismatch     `json:"mismatches"`
	// Free is true when this call used the project's free first inference.
	Free bool `json:"free,omitempty"`
}

// InferContext asks the backend to draft an org context from the founder's
// plain description plus the local fingerprint (names only, never code or env
// values). projectID is a stable client-side hash identifying the project;
// existing is the current context when this is a re-run (may be nil). The
// first inference per project is free; later ones cost Trojan Tokens and
// return an InsufficientTokensError (errors.Is ErrInsufficientTokens) on 402.
func InferContext(description string, fp fingerprint.Fingerprint, projectID string, existing *orgcontext.OrgContext, accessToken string) (*InferContextResult, error) {
	payload := map[string]any{
		"description": description,
		"fingerprint": fp,
		"project_id":  projectID,
	}
	if existing != nil {
		payload["existing_context"] = existing
	}
	inner, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	// base64-wrapped so Cloudflare's WAF never sees raw route/path strings.
	body, err := json.Marshal(map[string]string{"encoded": base64.StdEncoding.EncodeToString(inner)})
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(http.MethodPost, inferContextURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 90 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("infer-context request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusPaymentRequired {
		var e struct {
			Message string `json:"message"`
			Balance int    `json:"balance"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&e)
		return nil, &InsufficientTokensError{Balance: e.Balance, Message: e.Message}
	}
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("infer-context failed (status %d): %s", resp.StatusCode, string(msg))
	}

	var out InferContextResult
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("infer-context: bad response: %w", err)
	}
	return &out, nil
}
