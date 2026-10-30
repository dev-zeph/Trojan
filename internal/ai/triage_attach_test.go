package ai

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/dev-zeph/trojan/internal/normalizer"
)

// fakeTriageServer decodes the base64-wrapped triage request and answers with
// whatever reply(findings, call) returns. It records every request's findings.
type fakeTriageServer struct {
	mu    sync.Mutex
	calls [][]triageFindingWire
	reply func(fs []triageFindingWire, call int) []Verdict
}

func (s *fakeTriageServer) start(t *testing.T) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var env struct{ Encoded string }
		if err := json.NewDecoder(r.Body).Decode(&env); err != nil {
			t.Errorf("decode envelope: %v", err)
		}
		raw, err := base64.StdEncoding.DecodeString(env.Encoded)
		if err != nil {
			t.Errorf("decode base64: %v", err)
		}
		var body struct{ Findings []triageFindingWire }
		if err := json.Unmarshal(raw, &body); err != nil {
			t.Errorf("decode findings: %v", err)
		}
		s.mu.Lock()
		s.calls = append(s.calls, body.Findings)
		call := len(s.calls)
		s.mu.Unlock()
		json.NewEncoder(w).Encode(map[string]any{"verdicts": s.reply(body.Findings, call)}) //nolint:errcheck
	}))
	orig := triageURL
	triageURL = srv.URL
	t.Cleanup(func() { triageURL = orig; srv.Close() })
}

// verdictFor writes a rationale that names the finding's title, so a test can
// tell whose verdict landed where.
func verdictFor(f triageFindingWire, key string) Verdict {
	return Verdict{ID: key, Verdict: "confirmed", Confidence: 0.9, Rationale: "about: " + f.Title}
}

func websiteFindings() []normalizer.Finding {
	return []normalizer.Finding{
		{ID: "nuclei-1", Category: "dast", Title: "React Server Components RCE", FilePath: "http://x/"},
		{ID: "nuclei-10", Category: "dast", Title: "Missing CSP header", FilePath: "http://x/"},
		{ID: "agentic-a0d74d6e85f0", Category: "dast", Title: "Health endpoint leaks process env", FilePath: "http://x/api/health?verbose=1"},
		{ID: "agentic-a0d74d6e85f1", Category: "dast", Title: "Bookings BOLA: no ownership check", FilePath: "http://x/api/bookings/{id}"},
		{ID: "agentic-a0d74d6e85f", Category: "dast", Title: "SQL injection in admin customer search", FilePath: "http://x/api/admin/customers?q="},
	}
}

// (a) Similar/colliding-looking IDs, a reply in shuffled order, and a duplicate
// key: every finding still gets exactly its own verdict.
func TestTriageFindings_VerdictsLandOnTheRightFinding(t *testing.T) {
	s := &fakeTriageServer{reply: func(fs []triageFindingWire, call int) []Verdict {
		var out []Verdict
		// Reverse order, so position in the reply means nothing.
		for i := len(fs) - 1; i >= 0; i-- {
			out = append(out, verdictFor(fs[i], fs[i].ID))
		}
		// A stray duplicate for the first key (what made the health finding
		// carry the bookings rationale): must not overwrite the real one.
		out = append(out, Verdict{ID: fs[0].ID, Verdict: "likely_fp", Rationale: "about: SOMETHING ELSE"})
		// A key that names no finding is ignored.
		out = append(out, Verdict{ID: "agentic-a0d74d6e85f0", Verdict: "confirmed", Rationale: "stray"})
		return out
	}}
	s.start(t)

	fs := websiteFindings()
	got, err := TriageFindings(fs, "tok")
	if err != nil {
		t.Fatal(err)
	}
	if len(s.calls) != 1 {
		t.Fatalf("expected one request, got %d", len(s.calls))
	}
	for i, w := range s.calls[0] {
		if w.ID != batchKey(i) {
			t.Errorf("wire id %d = %q, want positional key %q (real IDs must not be sent)", i, w.ID, batchKey(i))
		}
	}
	for _, f := range fs {
		v, ok := got[f.ID]
		if !ok {
			t.Fatalf("no verdict for %s", f.ID)
		}
		if v.ID != f.ID || v.Rationale != "about: "+f.Title || v.Missing {
			t.Errorf("%s got %+v, want its own rationale", f.ID, v)
		}
	}
}

// (a) Findings that arrive with duplicate or empty IDs: after
// EnsureUniqueIDs each gets its own verdict instead of sharing one.
func TestTriageFindings_DuplicateIDsGetDistinctVerdicts(t *testing.T) {
	s := &fakeTriageServer{reply: func(fs []triageFindingWire, _ int) []Verdict {
		out := make([]Verdict, len(fs))
		for i, f := range fs {
			out[i] = verdictFor(f, f.ID)
		}
		return out
	}}
	s.start(t)

	fs := []normalizer.Finding{
		{ID: "nuclei-0", Title: "Exposed .git"},
		{ID: "nuclei-0", Title: "Directory listing"},
		{ID: "", Title: "Open redirect"},
		{ID: "", Title: "Verbose errors"},
	}
	normalizer.EnsureUniqueIDs(fs)
	got, err := TriageFindings(fs, "tok")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(fs) {
		t.Fatalf("got %d verdicts for %d findings: %+v", len(got), len(fs), got)
	}
	for _, f := range fs {
		if got[f.ID].Rationale != "about: "+f.Title {
			t.Errorf("%s (%s) got %q", f.ID, f.Title, got[f.ID].Rationale)
		}
	}
}

// (b) A finding the model never returns a verdict for is retried once, then
// reported as missing with a generic rationale, never a neighbour's text.
func TestTriageFindings_MissingVerdictIsReportedNotBorrowed(t *testing.T) {
	const dropped = "Bookings BOLA: no ownership check"
	s := &fakeTriageServer{reply: func(fs []triageFindingWire, _ int) []Verdict {
		var out []Verdict
		for _, f := range fs {
			if f.Title == dropped {
				continue
			}
			out = append(out, verdictFor(f, f.ID))
		}
		return out
	}}
	s.start(t)

	fs := websiteFindings()
	got, err := TriageFindings(fs, "tok")
	if err != nil {
		t.Fatal(err)
	}
	if len(s.calls) != 2 || len(s.calls[1]) != 1 || s.calls[1][0].Title != dropped {
		t.Fatalf("expected one retry with only the dropped finding, calls=%+v", s.calls)
	}
	v := got["agentic-a0d74d6e85f1"]
	if !v.Missing || v.Verdict != "needs_manual" || v.Rationale != noVerdictRationale || v.Confidence != 0 {
		t.Errorf("dropped finding got %+v, want the missing placeholder", v)
	}
	for _, f := range fs {
		if f.Title == dropped {
			continue
		}
		if got[f.ID].Rationale != "about: "+f.Title {
			t.Errorf("%s got %q", f.ID, got[f.ID].Rationale)
		}
	}
}

// (b) The retry recovers a dropped verdict, and the old edge function's
// "No verdict returned" filler is not trusted as a real verdict.
func TestTriageFindings_RetryRecoversDroppedVerdict(t *testing.T) {
	s := &fakeTriageServer{reply: func(fs []triageFindingWire, call int) []Verdict {
		out := make([]Verdict, len(fs))
		for i, f := range fs {
			out[i] = verdictFor(f, f.ID)
		}
		if call == 1 {
			out[1] = Verdict{ID: fs[1].ID, Verdict: "needs_manual", Confidence: 0, Rationale: "No verdict returned; flagged for manual review."}
		}
		return out
	}}
	s.start(t)

	fs := websiteFindings()
	got, err := TriageFindings(fs, "tok")
	if err != nil {
		t.Fatal(err)
	}
	if v := got[fs[1].ID]; v.Missing || v.Rationale != "about: "+fs[1].Title {
		t.Errorf("retry did not recover the verdict: %+v", v)
	}
}

// The escalation pass must never replace a real verdict with a placeholder.
func TestTriageWithContext_PlaceholderNeverOverwritesRealVerdict(t *testing.T) {
	orig := triageImpl
	t.Cleanup(func() { triageImpl = orig })
	pass := 0
	triageImpl = func(fs []normalizer.Finding, _ string) (map[string]Verdict, error) {
		pass++
		if pass == 1 {
			return map[string]Verdict{"a": {ID: "a", Verdict: "needs_manual", Confidence: 0.3, Rationale: "real but weak"}}, nil
		}
		return map[string]Verdict{"a": {ID: "a", Verdict: "needs_manual", Rationale: noVerdictRationale, Missing: true}}, nil
	}
	ret := &fakeRetriever{chunks: []RetrievedChunk{{FilePath: "x.ts", StartLine: 1, EndLine: 2, Text: "code"}}}
	got, err := TriageWithContext([]normalizer.Finding{{ID: "a", Title: "t"}}, "tok", ret)
	if err != nil {
		t.Fatal(err)
	}
	if got["a"].Rationale != "real but weak" {
		t.Errorf("placeholder overwrote the first-pass verdict: %+v", got["a"])
	}
}

// Agent findings send their evidence AND their rationale, plus any source
// location, so the model has what it needs to confirm them.
func TestBuildTriageWire_SendsEvidenceRationaleAndSource(t *testing.T) {
	w := buildTriageWire([]normalizer.Finding{{
		ID: "agentic-1", Category: "dast", Title: "SQLi", FilePath: "http://x/api/q", URL: "http://x/api/q",
		CodeSnippet: "GET /api/q?q=' returned a SQL error", RawMessage: "q is concatenated into SQL",
		SourceFile: "app/api/q/route.ts", SourceLine: 7, SurroundingCode: "export async function GET() {}",
	}})[0]
	if w.ID != "f1" || w.MatchedAt != "http://x/api/q" || w.Evidence == "" ||
		w.Rationale != "q is concatenated into SQL" || w.SourceFile != "app/api/q/route.ts" || w.SourceLine != 7 ||
		!strings.Contains(w.ResponseSnippet, "function GET") {
		t.Errorf("wire = %+v", w)
	}
}
