package ai

import (
	"strings"
	"testing"

	"github.com/dev-zeph/trojan/internal/normalizer"
)

type fakeRetriever struct {
	chunks  []RetrievedChunk
	queries []string
}

func (f *fakeRetriever) Retrieve(query string, k int) ([]RetrievedChunk, error) {
	f.queries = append(f.queries, query)
	return f.chunks, nil
}

func TestTriageWithContext_EscalatesWeakVerdicts(t *testing.T) {
	findings := []normalizer.Finding{
		{ID: "a", Title: "SQLi", CodeSnippet: "db.Query(q)", SurroundingCode: "func h(){}"},
		{ID: "b", Title: "XSS", SurroundingCode: "func g(){}"},
	}

	// First pass: "a" is weak (needs_manual), "b" is confident.
	// Second pass (escalation of "a"): now confident.
	pass := 0
	orig := triageImpl
	triageImpl = func(fs []normalizer.Finding, _ string) (map[string]Verdict, error) {
		pass++
		if pass == 1 {
			return map[string]Verdict{
				"a": {ID: "a", Verdict: "needs_manual", Confidence: 0.2},
				"b": {ID: "b", Verdict: "confirmed", Confidence: 0.95},
			}, nil
		}
		// Escalation pass should receive only "a", now with retrieved context.
		if len(fs) != 1 || fs[0].ID != "a" {
			t.Errorf("escalation batch = %+v, want only [a]", fs)
		}
		if !strings.Contains(fs[0].SurroundingCode, "Related code retrieved") {
			t.Errorf("escalated finding missing retrieved context: %s", fs[0].SurroundingCode)
		}
		if !strings.Contains(fs[0].SurroundingCode, "func sanitize") {
			t.Errorf("retrieved chunk not injected: %s", fs[0].SurroundingCode)
		}
		return map[string]Verdict{"a": {ID: "a", Verdict: "likely_fp", Confidence: 0.9}}, nil
	}
	defer func() { triageImpl = orig }()

	ret := &fakeRetriever{chunks: []RetrievedChunk{
		{FilePath: "util.go", StartLine: 10, EndLine: 12, Text: "func sanitize(q string) string { /* ... */ }"},
	}}

	verdicts, err := TriageWithContext(findings, "tok", ret)
	if err != nil {
		t.Fatal(err)
	}
	if pass != 2 {
		t.Errorf("expected 2 triage passes (initial + escalation), got %d", pass)
	}
	// "a" was re-triaged -> overwritten to likely_fp; "b" untouched.
	if verdicts["a"].Verdict != "likely_fp" {
		t.Errorf("a verdict = %q, want likely_fp (escalated)", verdicts["a"].Verdict)
	}
	if verdicts["b"].Verdict != "confirmed" {
		t.Errorf("b verdict = %q, want confirmed (untouched)", verdicts["b"].Verdict)
	}
	// Only the weak finding should have been queried.
	if len(ret.queries) != 1 || !strings.Contains(ret.queries[0], "SQLi") {
		t.Errorf("retriever queries = %v, want one for SQLi", ret.queries)
	}
}

func TestTriageWithContext_NilRetrieverIsPlainTriage(t *testing.T) {
	orig := triageImpl
	calls := 0
	triageImpl = func(fs []normalizer.Finding, _ string) (map[string]Verdict, error) {
		calls++
		return map[string]Verdict{"a": {ID: "a", Verdict: "needs_manual", Confidence: 0.1}}, nil
	}
	defer func() { triageImpl = orig }()

	v, err := TriageWithContext([]normalizer.Finding{{ID: "a"}}, "tok", nil)
	if err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Errorf("nil retriever should triage once, got %d calls", calls)
	}
	if v["a"].Verdict != "needs_manual" {
		t.Errorf("verdict should pass through unchanged, got %q", v["a"].Verdict)
	}
}

func TestTriageWithContext_NoWeakFindingsSkipsEscalation(t *testing.T) {
	orig := triageImpl
	calls := 0
	triageImpl = func(fs []normalizer.Finding, _ string) (map[string]Verdict, error) {
		calls++
		return map[string]Verdict{"a": {ID: "a", Verdict: "confirmed", Confidence: 0.9}}, nil
	}
	defer func() { triageImpl = orig }()

	ret := &fakeRetriever{chunks: []RetrievedChunk{{FilePath: "x.go", Text: "y"}}}
	_, err := TriageWithContext([]normalizer.Finding{{ID: "a"}}, "tok", ret)
	if err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Errorf("confident verdicts should not escalate; want 1 triage call, got %d", calls)
	}
	if len(ret.queries) != 0 {
		t.Errorf("no retrieval expected for confident findings, got %v", ret.queries)
	}
}
