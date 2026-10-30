package main

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	whitebox "github.com/dev-zeph/trojan/internal/agent"
	"github.com/dev-zeph/trojan/internal/dast/agent"
	"github.com/dev-zeph/trojan/internal/memory"
)

// copyVibeapp copies the shared fixture into a temp dir so tests can write
// .trojan/ state without touching the repo.
func copyVibeapp(t *testing.T) string {
	t.Helper()
	src := filepath.Join("..", "..", "internal", "testdata", "vibeapp")
	dst := t.TempDir()
	err := filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		if d.IsDir() {
			return os.MkdirAll(filepath.Join(dst, rel), 0o755)
		}
		b, rerr := os.ReadFile(p)
		if rerr != nil {
			return rerr
		}
		return os.WriteFile(filepath.Join(dst, rel), b, 0o644)
	})
	if err != nil {
		t.Fatal(err)
	}
	return dst
}

const testContextYAML = `app:
  name: Vibe Shop
  description: A small storefront where customers place orders and read posts.
sensitive_data:
  - category: PII
    description: Customer emails
auth_model:
  who_logs_in: customers and shop staff
  roles: [customer, admin]
  admin_area: true
third_party_services: [Stripe, Supabase]
data_stores: [orders, profiles]
`

func TestBuildBrainSeed_AllSections(t *testing.T) {
	root := copyVibeapp(t)
	if err := os.MkdirAll(filepath.Join(root, ".trojan"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".trojan", "context.yaml"), []byte(testContextYAML), 0o644); err != nil {
		t.Fatal(err)
	}
	st, err := memory.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range []memory.Event{
		{Kind: memory.KindConfirmed, File: "app/api/orders/route.ts", RuleID: "idor", Title: "Orders readable by any user", Evidence: "GET /api/orders/2 as user 1 returned 200", Source: memory.SourceAgent},
		{Kind: memory.KindFact, RuleID: "fact1", Title: "Orders use sequential ids", Source: memory.SourceAgent},
		{Kind: memory.KindAttackStep, File: "/api/orders/2", RuleID: "step1", Title: "Changed order id in path", Evidence: "swap id 1 for 2", Source: memory.SourceAgent},
		{Kind: memory.KindFalsePositive, File: "app/page.tsx", RuleID: "xss", Title: "dangerouslySetInnerHTML in landing page", Source: memory.SourceUser},
	} {
		if err := st.Record(e); err != nil {
			t.Fatal(err)
		}
	}
	st.Close()

	seed := buildBrainSeed(root)
	for _, want := range []string{
		"APP CONTEXT", "Vibe Shop", "PII", "admin area", "Stripe",
		"CODE GRAPH", "Unguarded entrypoints", "app/api/orders/route.ts", "orders",
		"MEMORY FROM PAST RUNS", "Orders readable by any user", "Orders use sequential ids",
		"Changed order id in path", "Known false positives", "dangerouslySetInnerHTML",
	} {
		if !strings.Contains(seed, want) {
			t.Errorf("seed missing %q\n---\n%s", want, seed)
		}
	}
	if len(seed) > brainSeedCap {
		t.Errorf("seed is %d chars, cap %d", len(seed), brainSeedCap)
	}
}

func TestBuildBrainSeed_CapHolds(t *testing.T) {
	root := t.TempDir()
	st, err := memory.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	long := strings.Repeat("evidence ", 200)
	for i := 0; i < 40; i++ {
		st.Record(memory.Event{Kind: memory.KindFact, RuleID: string(rune('a' + i)), Title: long, Evidence: long, Source: memory.SourceAgent})      //nolint:errcheck
		st.Record(memory.Event{Kind: memory.KindConfirmed, RuleID: string(rune('a' + i)), Title: long, Evidence: long, Source: memory.SourceAgent}) //nolint:errcheck
	}
	st.Close()
	if seed := buildBrainSeed(root); seed == "" || len(seed) > brainSeedCap {
		t.Errorf("seed len %d, want 1..%d", len(seed), brainSeedCap)
	}
}

func TestBuildBrainSeed_NothingKnown(t *testing.T) {
	if got := buildBrainSeed(t.TempDir()); got != "" {
		t.Errorf("empty project should give empty seed, got %q", got)
	}
	if got := buildBrainSeed(""); got != "" {
		t.Errorf("no project should give empty seed, got %q", got)
	}
	// Reading must not create memory in a folder that has none.
	d := t.TempDir()
	buildBrainSeed(d)
	if _, err := os.Stat(filepath.Join(d, ".trojan", "memory.db")); err == nil {
		t.Error("seed building created a memory db")
	}
}

// A scripted finalize: agent candidates become findings, triage confirms one,
// and learn() must write a confirmed event (plus an attack step) and nothing
// for the unconfirmed one.
func TestBrainLearn_RecordsConfirmed(t *testing.T) {
	root := t.TempDir()
	b := openBrain(root, "http://localhost:3000")
	defer b.close()
	if b.store == nil {
		t.Fatal("memory did not open")
	}

	cands := []agent.Candidate{
		{Title: "IDOR on orders", Severity: "high", URL: "http://localhost:3000/api/orders/2", Evidence: "200 with another user's order", Rationale: "no ownership check"},
		{Title: "Verbose error", Severity: "low", URL: "http://localhost:3000/api/x", Evidence: "stack trace", Rationale: "debug on"},
	}
	findings := agenticFindingsFromCandidates(cands)
	findings[0].Verdict = "confirmed"
	findings[1].Verdict = "needs_manual"

	if n := b.learn(findings, cands); n != 1 {
		t.Fatalf("learn recorded %d confirmed events, want 1", n)
	}
	all, err := b.store.All()
	if err != nil {
		t.Fatal(err)
	}
	var confirmed, steps int
	for _, e := range all {
		switch e.Kind {
		case memory.KindConfirmed:
			confirmed++
			if e.Title != "IDOR on orders" || e.Source != memory.SourceAgent {
				t.Errorf("unexpected confirmed event %+v", e)
			}
		case memory.KindAttackStep:
			steps++
			if !strings.Contains(e.Evidence, "another user's order") {
				t.Errorf("attack step lost its evidence: %+v", e)
			}
		}
	}
	if confirmed != 1 || steps != 1 {
		t.Errorf("confirmed=%d steps=%d, want 1/1 (%+v)", confirmed, steps, all)
	}
}

// A saved hypotheses.json adds a capped "HYPOTHESES TO PROVE" section to the
// seed, with the stable node keys the pen test needs.
func TestBrainSeed_HypothesesSection(t *testing.T) {
	root := t.TempDir()
	if err := whitebox.SaveHypotheses(root, whitebox.HypothesisFile{
		Hypotheses: []whitebox.Hypothesis{{
			ID: "H1", Title: "Public order write",
			NodeKeys: []string{"app/api/orders/route.ts#POST", "datastore:orders"},
			Class:    "missing-auth", Method: "POST", Path: "/api/orders",
			ExpectedEvidence: "unauth POST returns 200 and a row appears in orders",
			Confidence:       "high",
		}},
	}); err != nil {
		t.Fatal(err)
	}
	seed := buildBrainSeed(root)
	for _, want := range []string{
		"HYPOTHESES TO PROVE", "Public order write",
		"POST /api/orders", "app/api/orders/route.ts#POST", "datastore:orders",
	} {
		if !strings.Contains(seed, want) {
			t.Errorf("seed missing %q\n---\n%s", want, seed)
		}
	}
	if len(seed) > brainSeedCap {
		t.Errorf("seed is %d chars, over cap %d", len(seed), brainSeedCap)
	}
}

// The section stays bounded even with many long hypotheses (overflow marker).
func TestHypothesesSection_Capped(t *testing.T) {
	var hyps []whitebox.Hypothesis
	for i := 0; i < 30; i++ {
		hyps = append(hyps, whitebox.Hypothesis{
			ID: "H", Title: strings.Repeat("long title ", 20),
			NodeKeys: []string{"app/api/x/route.ts#POST"}, Class: "missing-auth",
			Method: "POST", Path: "/api/x", ExpectedEvidence: strings.Repeat("evidence ", 20),
			Confidence: "medium",
		})
	}
	s := hypothesesSectionFrom(hyps)
	if !strings.Contains(s, "more") {
		t.Errorf("want an overflow marker when over brainMaxHyps, got:\n%s", s)
	}
}

// Unproven hypotheses are recorded as a dated "tested, not proven" fact;
// proven ones are left to learn (so recordHypothesisOutcomes skips them).
func TestRecordHypothesisOutcomes(t *testing.T) {
	root := t.TempDir()
	b := openBrain(root, "http://localhost:3000")
	defer b.close()

	hyps := []whitebox.Hypothesis{
		{ID: "H1", Title: "Public order write", Class: "missing-auth", Method: "POST", Path: "/api/orders", NodeKeys: []string{"datastore:orders"}},
		{ID: "H2", Title: "SQLi in export", Class: "sql-injection", Method: "GET", Path: "/api/export", NodeKeys: []string{"datastore:invoices"}},
	}
	cands := []agent.Candidate{
		{Title: "Public order write", Severity: "high", URL: "http://localhost:3000/api/orders", Evidence: "200 unauth"},
	}
	findings := agenticFindingsFromCandidates(cands)
	findings[0].Verdict = "confirmed" // proves H1 by path

	b.recordHypothesisOutcomes(hyps, findings)

	all, err := b.store.All()
	if err != nil {
		t.Fatal(err)
	}
	var facts int
	for _, e := range all {
		if e.Kind == memory.KindFact && strings.HasPrefix(e.Title, "Tested, not proven") {
			facts++
			if !strings.Contains(e.Title, "SQLi in export") {
				t.Errorf("wrong unproven hypothesis recorded: %+v", e)
			}
		}
	}
	if facts != 1 {
		t.Errorf("want exactly 1 unproven fact (H2), got %d: %+v", facts, all)
	}
}

// --no-hypothesize (and black-box / no project root) must skip the white-box
// step before any graph build or network call: no hypotheses file appears.
// The access token is junk, so reaching the transport would fail loudly.
func TestRunHypothesizeStep_Skips(t *testing.T) {
	root := copyVibeapp(t)
	for name, c := range map[string]struct {
		root            string
		greyBox, noHypo bool
	}{
		"no-hypothesize": {root, true, true},
		"black-box":      {root, false, false},
		"no-root":        {"", true, false},
	} {
		if got := runHypothesizeStep(c.root, "junk-token", c.greyBox, c.noHypo); got != nil {
			t.Errorf("%s: want skip (nil), got %+v", name, got)
		}
	}
	if _, err := os.Stat(filepath.Join(root, ".trojan", "hypotheses.json")); err == nil {
		t.Error("skipped step must not write .trojan/hypotheses.json")
	}
}

// With no project root the memory lives in the site's website-test folder.
func TestOpenBrain_SiteMemory(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	b := openBrain("", "http://localhost:3000")
	defer b.close()
	if b.store == nil || b.memRoot == "" {
		t.Fatal("no site-level memory")
	}
	if !strings.HasPrefix(b.memRoot, home) {
		t.Errorf("memRoot %q not under HOME", b.memRoot)
	}
}
