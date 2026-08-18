package rag_test

import (
	"os"
	"testing"

	"github.com/dev-zeph/trojan/internal/ai"
	"github.com/dev-zeph/trojan/internal/config"
	"github.com/dev-zeph/trojan/internal/rag"
)

// TestLiveRetrieval exercises the real embed edge function + local store against
// an already-built index. Gated on TROJAN_LIVE_INDEX_DIR so it never runs in CI;
// point it at a directory that has a .trojan/index built by `trojan index`.
//
//	TROJAN_LIVE_INDEX_DIR=/path/to/ragfix go test ./internal/rag -run TestLiveRetrieval -v
func TestLiveRetrieval(t *testing.T) {
	dir := os.Getenv("TROJAN_LIVE_INDEX_DIR")
	if dir == "" {
		t.Skip("set TROJAN_LIVE_INDEX_DIR to run the live retrieval test")
	}
	cfg, err := config.LoadConfig()
	if err != nil || cfg.AccessToken == "" {
		t.Skip("not logged in")
	}

	r, err := rag.NewRetriever(dir, ai.NewEmbedder(cfg.AccessToken))
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("index has %d chunks, dim=%d", len(r.Store.Entries), r.Store.Dim)

	// Query about the vulnerable handler; the distant Sanitize function should
	// surface even though nothing lexically links them.
	res, err := r.Retrieve("SQL injection: user id interpolated into SELECT query in GetUser", 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(res) == 0 {
		t.Fatal("no results")
	}
	for i, c := range res {
		t.Logf("#%d score=%.3f %s:%d-%d %q", i, c.Score, c.Chunk.FilePath, c.Chunk.StartLine, c.Chunk.EndLine, c.Chunk.Symbol)
	}
	var foundSanitize bool
	for _, c := range res {
		if c.Chunk.Symbol == "func Sanitize" {
			foundSanitize = true
		}
	}
	if !foundSanitize {
		t.Errorf("expected the distant Sanitize function in top-3 (the RAG-helps case)")
	}
}
