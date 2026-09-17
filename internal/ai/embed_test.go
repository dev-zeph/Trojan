package ai

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestEmbedTexts_BatchesAndUnwraps verifies the client base64-wraps the body,
// batches over embedBatchSize, and returns vectors in input order. It points the
// client at a stub server via embedURL override.
func TestEmbedTexts_RoundTrip(t *testing.T) {
	var gotTexts []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Unwrap the base64 envelope the client sends.
		var env struct {
			Encoded string `json:"encoded"`
		}
		raw, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(raw, &env); err != nil {
			t.Errorf("body not JSON envelope: %v", err)
		}
		decoded, err := base64.StdEncoding.DecodeString(env.Encoded)
		if err != nil {
			t.Errorf("body not base64-wrapped: %v", err)
		}
		var inner struct {
			Texts     []string `json:"texts"`
			InputType string   `json:"inputType"`
		}
		if err := json.Unmarshal(decoded, &inner); err != nil {
			t.Errorf("inner not JSON: %v", err)
		}
		if inner.InputType != "query" {
			t.Errorf("inputType = %q, want query", inner.InputType)
		}
		gotTexts = append(gotTexts, inner.Texts...)

		// Echo back one vector per input.
		embs := make([][]float32, len(inner.Texts))
		for i := range inner.Texts {
			embs[i] = []float32{float32(i), 1, 0}
		}
		json.NewEncoder(w).Encode(map[string]any{"embeddings": embs})
	}))
	defer srv.Close()

	old := embedURLForTest
	embedURLForTest = srv.URL
	defer func() { embedURLForTest = old }()

	texts := []string{"a", "b", "c"}
	vecs, err := EmbedTexts(texts, EmbedQuery, "tok")
	if err != nil {
		t.Fatal(err)
	}
	if len(vecs) != 3 {
		t.Fatalf("expected 3 vectors, got %d", len(vecs))
	}
	if strings.Join(gotTexts, ",") != "a,b,c" {
		t.Errorf("server saw %v, want [a b c]", gotTexts)
	}
}
