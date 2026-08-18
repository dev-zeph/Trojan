package ai

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

const embedBatchSize = 128 // must match MAX_TEXTS in the embed edge function

// embedURLForTest is the embed endpoint; a package var so tests can point it at
// a stub server. Production value is the deployed edge function.
var embedURLForTest = "https://dtmocojzvgsswjdsrmqr.supabase.co/functions/v1/embed"

// EmbedInputType tells the provider whether texts are documents being indexed or
// a search query — Voyage embeds them slightly differently for better retrieval.
type EmbedInputType string

const (
	EmbedDocument EmbedInputType = "document"
	EmbedQuery    EmbedInputType = "query"
)

// Embedder adapts EmbedTexts to the rag.Embedder interface (which it satisfies
// structurally — no import of internal/rag, so no cycle when rag is the caller).
// It captures the Pro access token so the retrieval layer stays token-agnostic.
type Embedder struct{ AccessToken string }

// NewEmbedder returns an Embedder for the given Pro access token.
func NewEmbedder(accessToken string) *Embedder { return &Embedder{AccessToken: accessToken} }

// Embed implements rag.Embedder.
func (e *Embedder) Embed(texts []string, inputType string) ([][]float32, error) {
	return EmbedTexts(texts, EmbedInputType(inputType), e.AccessToken)
}

// EmbedTexts returns one embedding vector per input text, in the same order.
// Texts are sent in batches and base64-wrapped ({ "encoded": ... }) so
// Cloudflare's WAF doesn't 403 on source containing attack signatures; the embed
// edge function unwraps via _shared/body.ts and holds the provider key. On a
// batch error the embeddings gathered so far are returned alongside the error.
func EmbedTexts(texts []string, inputType EmbedInputType, accessToken string) ([][]float32, error) {
	out := make([][]float32, 0, len(texts))
	for start := 0; start < len(texts); start += embedBatchSize {
		end := min(start+embedBatchSize, len(texts))
		vecs, err := embedBatch(texts[start:end], inputType, accessToken)
		if err != nil {
			return out, err
		}
		out = append(out, vecs...)
	}
	return out, nil
}

func embedBatch(texts []string, inputType EmbedInputType, accessToken string) ([][]float32, error) {
	if inputType == "" {
		inputType = EmbedDocument
	}
	inner, err := json.Marshal(map[string]any{
		"texts":     texts,
		"inputType": string(inputType),
	})
	if err != nil {
		return nil, err
	}
	body, err := json.Marshal(map[string]string{"encoded": base64.StdEncoding.EncodeToString(inner)})
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(http.MethodPost, embedURLForTest, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("embed request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusTooManyRequests {
		return nil, fmt.Errorf("rate_limit_exceeded")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("embed failed (status %d)", resp.StatusCode)
	}

	var result struct {
		Embeddings [][]float32 `json:"embeddings"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	return result.Embeddings, nil
}
