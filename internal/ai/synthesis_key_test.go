package ai

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/dev-zeph/trojan/internal/normalizer"
)

// (c) Every agent finding shares RuleID "agentic", and the synthesize edge
// function caches by rule id, so they all got one shared explanation. Each must
// now reach the backend under its own rule id and get its own explanation,
// while real scanner rules keep theirs (so their cache still works).
func TestSynthesizeFinding_ExplanationsArePerFinding(t *testing.T) {
	t.Setenv("HOME", t.TempDir()) // isolate the local explanation cache

	var mu sync.Mutex
	seen := map[string]bool{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var p struct {
			RuleID string `json:"ruleId"`
			Title  string `json:"title"`
		}
		json.NewDecoder(r.Body).Decode(&p) //nolint:errcheck
		mu.Lock()
		seen[p.RuleID] = true
		mu.Unlock()
		// Simulate the server cache: the answer depends on the rule id only.
		json.NewEncoder(w).Encode(Synthesis{Simply: "explains " + p.RuleID, Actions: []string{"fix " + p.Title}}) //nolint:errcheck
	}))
	defer srv.Close()
	defer OverrideSynthesizeURL(srv.URL)()

	login := normalizer.Finding{ID: "agentic-1", Scanner: "agentic-dast", Category: "dast", RuleID: "agentic",
		Title: "SQL injection login bypass", FilePath: "http://x/api/auth/login", CodeSnippet: "POST /api/auth/login ' OR 1=1"}
	health := normalizer.Finding{ID: "agentic-2", Scanner: "agentic-dast", Category: "dast", RuleID: "agentic",
		Title: "Health endpoint leaks env", FilePath: "http://x/api/health?verbose=1", CodeSnippet: "GET /api/health?verbose=1 -> env"}

	a, err := SynthesizeFinding(login, "tok", 1, "")
	if err != nil {
		t.Fatal(err)
	}
	b, err := SynthesizeFinding(health, "tok", 1, "")
	if err != nil {
		t.Fatal(err)
	}
	if a.Simply == b.Simply {
		t.Fatalf("two different agent findings got the same explanation %q", a.Simply)
	}
	if synthesisRuleID(login) == "agentic" || synthesisRuleID(login) == synthesisRuleID(health) {
		t.Errorf("agentic rule ids not per finding: %q %q", synthesisRuleID(login), synthesisRuleID(health))
	}
	if cachePath(login, 1) == cachePath(health, 1) {
		t.Error("agentic findings share a local cache entry")
	}

	semgrep := normalizer.Finding{Scanner: "semgrep", RuleID: "go.lang.security.sqli", Title: "SQLi"}
	if got := synthesisRuleID(semgrep); got != "go.lang.security.sqli" {
		t.Errorf("scanner rule id changed: %q", got)
	}
	if got := synthesisRuleID(normalizer.Finding{Title: "x"}); got == "" || got == "finding" {
		t.Errorf("empty rule id not made per finding: %q", got)
	}
}
