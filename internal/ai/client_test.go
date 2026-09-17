package ai

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/dev-zeph/trojan/internal/normalizer"
)

// withSynthesizeURL points SynthesizeFinding at a test server for the
// duration of the test and restores the real endpoint on cleanup.
func withSynthesizeURL(t *testing.T, url string) {
	t.Helper()
	orig := synthesizeURL
	synthesizeURL = url
	t.Cleanup(func() { synthesizeURL = orig })
}

// testFinding builds a finding whose cache key (derived from CodeSnippet +
// FilePath + familiarity) is unique to ruleID, and schedules removal of
// whatever cache file SynthesizeFinding writes for it so tests don't leak
// into ~/.trojan/cache or get a false cache hit on a later run.
func testFinding(t *testing.T, ruleID string) normalizer.Finding {
	t.Helper()
	f := normalizer.Finding{
		RuleID:      ruleID,
		Scanner:     "test-scanner",
		Category:    "test",
		Title:       "Test finding",
		FilePath:    "internal/ai/client_test.go",
		CodeSnippet: "const marker = \"" + ruleID + "\"",
	}
	t.Cleanup(func() { os.Remove(cachePath(f, 1)) })
	return f
}

func TestSynthesizeFinding_402ReturnsInsufficientTokensError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusPaymentRequired)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"error":   "insufficient_tokens",
			"message": "You're out of Trojan Tokens.",
			"balance": 0,
		})
	}))
	defer srv.Close()
	withSynthesizeURL(t, srv.URL)

	f := testFinding(t, "rule-402")

	_, err := SynthesizeFinding(f, "token", 1, "")
	if err == nil {
		t.Fatalf("expected an error for a 402 response, got nil")
	}
	if !errors.Is(err, ErrInsufficientTokens) {
		t.Fatalf("expected errors.Is(err, ErrInsufficientTokens) to hold, got: %v", err)
	}
	var ite *InsufficientTokensError
	if !errors.As(err, &ite) {
		t.Fatalf("expected errors.As to recover *InsufficientTokensError, got: %v", err)
	}
	if ite.Balance != 0 {
		t.Fatalf("expected balance 0, got %d", ite.Balance)
	}
	if ite.Message != "You're out of Trojan Tokens." {
		t.Fatalf("expected the edge function's message to carry through, got %q", ite.Message)
	}
}

func TestSynthesizeFinding_200ParsesNormally(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(Synthesis{
			Simply:  "This is risky because it trusts user input.",
			Actions: []string{"Validate the input", "Use a parameterized query"},
		})
	}))
	defer srv.Close()
	withSynthesizeURL(t, srv.URL)

	f := testFinding(t, "rule-200")

	s, err := SynthesizeFinding(f, "token", 1, "")
	if err != nil {
		t.Fatalf("expected no error on 200, got: %v", err)
	}
	if s.Simply != "This is risky because it trusts user input." {
		t.Fatalf("unexpected Simply: %q", s.Simply)
	}
	if len(s.Actions) != 2 {
		t.Fatalf("expected 2 actions, got: %+v", s.Actions)
	}
}

func TestSynthesizeFinding_GenericFailureIsNotInsufficientTokens(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	withSynthesizeURL(t, srv.URL)

	f := testFinding(t, "rule-500")

	_, err := SynthesizeFinding(f, "token", 1, "")
	if err == nil {
		t.Fatalf("expected an error for a 500 response, got nil")
	}
	if errors.Is(err, ErrInsufficientTokens) {
		t.Fatalf("a plain 500 should not be classified as insufficient tokens, got: %v", err)
	}
}

// TestSynthesizeFinding_CacheHitSkipsNetwork confirms a cached explanation is
// served without ever calling the edge function -- this is what keeps
// zero-balance users unblocked on findings they've already paid to explain.
func TestSynthesizeFinding_CacheHitSkipsNetwork(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusPaymentRequired)
	}))
	defer srv.Close()
	withSynthesizeURL(t, srv.URL)

	f := testFinding(t, "rule-cached")
	saveToCache(f, 1, &Synthesis{Simply: "cached explanation"})

	s, err := SynthesizeFinding(f, "token", 1, "")
	if err != nil {
		t.Fatalf("expected the cache hit to short-circuit without error, got: %v", err)
	}
	if s.Simply != "cached explanation" {
		t.Fatalf("expected the cached synthesis to be returned, got: %+v", s)
	}
	if called {
		t.Fatalf("expected the network to be skipped on a cache hit")
	}
}
