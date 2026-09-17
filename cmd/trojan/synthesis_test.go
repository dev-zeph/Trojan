package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/dev-zeph/trojan/internal/ai"
	"github.com/dev-zeph/trojan/internal/normalizer"
)

// TestSynthesizeConcurrently_StopsEarlyOnInsufficientTokens verifies that once
// the edge function reports a 402 (out of Trojan Tokens), synthesizeConcurrently
// stops scheduling new work instead of firing one doomed request per remaining
// finding. With maxConcurrent = 8, the number of requests actually made should
// stay near that bound even with far more findings queued up.
func TestSynthesizeConcurrently_StopsEarlyOnInsufficientTokens(t *testing.T) {
	t.Setenv("HOME", t.TempDir()) // isolate ~/.trojan/cache from the real cache

	var requests int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&requests, 1)
		w.WriteHeader(http.StatusPaymentRequired)
		_, _ = w.Write([]byte(`{"error":"insufficient_tokens","message":"out of tokens","balance":0}`))
	}))
	defer srv.Close()
	restore := ai.OverrideSynthesizeURL(srv.URL)
	defer restore()

	const total = 40
	findings := make([]normalizer.Finding, total)
	idxs := make([]int, total)
	for i := range findings {
		// Distinct CodeSnippet per finding so each gets its own cache key and
		// none of them can short-circuit via a cache hit.
		findings[i] = normalizer.Finding{
			RuleID:      "rule",
			Scanner:     "test",
			FilePath:    "file.go",
			CodeSnippet: "snippet-" + strconv.Itoa(i),
		}
		idxs[i] = i
	}

	res := synthesizeConcurrently(findings, idxs, "token", 1, "")

	if !res.outOfTokens {
		t.Fatalf("expected outOfTokens to be true")
	}
	if res.completed != 0 {
		t.Fatalf("expected 0 completed findings, got %d", res.completed)
	}
	if res.unexplained != total {
		t.Fatalf("expected all %d findings unexplained, got %d", total, res.unexplained)
	}
	for i := range findings {
		if findings[i].Simply != "" {
			t.Fatalf("finding %d should not have been synthesized", i)
		}
	}

	got := atomic.LoadInt64(&requests)
	if got == 0 {
		t.Fatalf("expected at least one request to reach the stub server")
	}
	// maxConcurrent is 8: at most that many requests can already be in flight
	// when the first 402 lands, so the total fired should never approach the
	// full 40 findings queued up.
	if got > 8 {
		t.Fatalf("expected early stop to cap requests near maxConcurrent (8), got %d fired out of %d findings", got, total)
	}
}

// TestSynthesizeConcurrently_200ParsesAndFillsFindings is the counterpart
// happy path: every finding gets Simply/Actions populated and no early stop
// is triggered.
func TestSynthesizeConcurrently_200ParsesAndFillsFindings(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"simply":"explained","actions":["fix it"]}`))
	}))
	defer srv.Close()
	restore := ai.OverrideSynthesizeURL(srv.URL)
	defer restore()

	const total = 5
	findings := make([]normalizer.Finding, total)
	idxs := make([]int, total)
	for i := range findings {
		findings[i] = normalizer.Finding{
			RuleID:      "rule",
			Scanner:     "test",
			FilePath:    "file.go",
			CodeSnippet: "happy-" + strconv.Itoa(i),
		}
		idxs[i] = i
	}

	res := synthesizeConcurrently(findings, idxs, "token", 1, "")

	if res.outOfTokens {
		t.Fatalf("did not expect outOfTokens on a clean 200 run")
	}
	if res.completed != total {
		t.Fatalf("expected %d completed, got %d", total, res.completed)
	}
	for i := range findings {
		if findings[i].Simply != "explained" {
			t.Fatalf("finding %d was not synthesized: %+v", i, findings[i])
		}
	}
}

// TestPrintSynthesisSummary_ReportsOutOfTokensOnce checks the out-of-tokens
// footer names the cause and the unexplained count exactly once, rather than
// once per finding that never got synthesized.
func TestPrintSynthesisSummary_ReportsOutOfTokensOnce(t *testing.T) {
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w

	printSynthesisSummary(synthesisResult{outOfTokens: true, balance: 3, unexplained: 12, completed: 5}, 17)

	_ = w.Close()
	os.Stdout = old
	out, _ := io.ReadAll(r)
	text := string(out)

	if strings.Count(text, "Out of Trojan Tokens") != 1 {
		t.Fatalf("expected exactly one out-of-tokens message, got: %q", text)
	}
	if !strings.Contains(text, "12") {
		t.Fatalf("expected the unexplained count (12) in the message, got: %q", text)
	}
}
