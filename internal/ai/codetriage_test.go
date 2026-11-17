package ai

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/dev-zeph/trojan/internal/memory"
	"github.com/dev-zeph/trojan/internal/normalizer"
)

// Fixture: a project with a Bearer-style "hard-coded secret" that is really a
// form label, and one real-looking live key. No paid AI is called: the triage
// endpoint is a local stub that judges by the evidence it is sent.

const labelFile = `import React from "react"

export function LoginForm() {
  const labels = {
    email: "Email",
    password: "Password",
  }
  return <form>{labels.password}</form>
}
`

const keyFile = `// Server settings.
import { env } from "./env"

const timeoutMs = 3000

export const config = {
  region: "us-east-1",
  stripeSecret: "` + fakeLiveKey + `",
}
`

// fakeLiveKey is a made-up key in Stripe's live format, split so secret
// scanners (GitHub push protection, Gitleaks) don't flag this test file.
const fakeLiveKey = "sk_" + "live_" + "51HxQe2LkF9aZ0rT7wYbN3mVvC8dP"

func writeFixture(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	must := func(err error) {
		if err != nil {
			t.Fatal(err)
		}
	}
	must(os.MkdirAll(filepath.Join(root, "src"), 0o755))
	must(os.WriteFile(filepath.Join(root, "src", "LoginForm.tsx"), []byte(labelFile), 0o644))
	must(os.WriteFile(filepath.Join(root, "src", "config.ts"), []byte(keyFile), 0o644))
	return root
}

// fixtureFindings builds fresh findings, as each scan does. FilePath is
// project-relative, like Bearer reports it.
func fixtureFindings() []normalizer.Finding {
	return []normalizer.Finding{
		{
			ID: "bearer-label", Scanner: "bearer", Category: "sast", Severity: normalizer.SeverityCritical,
			Title: "Usage of hard-coded secret", RawMessage: "Hard-coded secrets in code are a risk.",
			FilePath: "src/LoginForm.tsx", LineNumber: 6, CodeSnippet: `password: "Password",`,
			RuleID: "javascript_lang_hardcoded_secret", Status: normalizer.StatusOpen,
		},
		{
			ID: "bearer-key", Scanner: "bearer", Category: "sast", Severity: normalizer.SeverityCritical,
			Title: "Usage of hard-coded secret", RawMessage: "Hard-coded secrets in code are a risk.",
			FilePath: "src/config.ts", LineNumber: 7, CodeSnippet: `stripeSecret: "` + fakeLiveKey + `",`,
			RuleID: "javascript_lang_hardcoded_secret", Status: normalizer.StatusOpen,
		},
	}
}

// judgeByEvidence is the stub model: a label value is a false alarm, a live
// key is real.
func judgeByEvidence(fs []triageFindingWire, _ int) []Verdict {
	out := make([]Verdict, 0, len(fs))
	for _, f := range fs {
		switch {
		case strings.Contains(f.Evidence, `"Password"`):
			out = append(out, Verdict{ID: f.ID, Verdict: "likely_fp", Confidence: 0.92, Rationale: "This is the text label for a password field, not a password."})
		case strings.Contains(f.Evidence, "sk_live_"):
			out = append(out, Verdict{ID: f.ID, Verdict: "confirmed", Confidence: 0.95, Rationale: "A live Stripe secret key is written in the code."})
		default:
			out = append(out, Verdict{ID: f.ID, Verdict: "needs_manual", Confidence: 0.5, Rationale: "unclear"})
		}
	}
	return out
}

func openStore(t *testing.T, root string) *memory.Store {
	t.Helper()
	s, err := memory.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func opts(root string, store *memory.Store) CodeTriageOptions {
	return CodeTriageOptions{ProjectRoot: root, AccessToken: "tok", Memory: store, Cache: store}
}

func byID(fs []normalizer.Finding) map[string]normalizer.Finding {
	m := map[string]normalizer.Finding{}
	for _, f := range fs {
		m[f.ID] = f
	}
	return m
}

func TestTriageCodeScan_HidesLabelKeepsRealSecret(t *testing.T) {
	root := writeFixture(t)
	srv := &fakeTriageServer{reply: judgeByEvidence}
	srv.start(t)
	store := openStore(t, root)

	fs := fixtureFindings()
	stats, err := TriageCodeScan(fs, opts(root, store))
	if err != nil {
		t.Fatal(err)
	}
	got := byID(fs)
	if !got["bearer-label"].HiddenAsFalseAlarm() || got["bearer-label"].VerdictReason == "" {
		t.Fatalf("label finding should be hidden with a reason: %+v", got["bearer-label"])
	}
	if got["bearer-key"].HiddenAsFalseAlarm() || got["bearer-key"].Verdict != "confirmed" {
		t.Fatalf("real key must stay visible: %+v", got["bearer-key"])
	}
	if stats.Hidden != 1 || stats.Checked != 2 || len(srv.calls) != 1 {
		t.Fatalf("stats %+v, calls %d", stats, len(srv.calls))
	}
	if normalizer.CountHiddenFalseAlarms(fs) != 1 {
		t.Fatal("hidden count")
	}
}

func TestTriageCodeScan_RescanUnchangedCodeIsFree(t *testing.T) {
	root := writeFixture(t)
	srv := &fakeTriageServer{reply: judgeByEvidence}
	srv.start(t)
	store := openStore(t, root)

	if _, err := TriageCodeScan(fixtureFindings(), opts(root, store)); err != nil {
		t.Fatal(err)
	}
	callsAfterFirst := len(srv.calls)

	fs := fixtureFindings() // a fresh scan
	stats, err := TriageCodeScan(fs, opts(root, store))
	if err != nil {
		t.Fatal(err)
	}
	if len(srv.calls) != callsAfterFirst {
		t.Fatalf("rescan of unchanged code made %d triage call(s)", len(srv.calls)-callsAfterFirst)
	}
	if stats.Cached != 2 || stats.Checked != 0 || stats.Hidden != 1 {
		t.Fatalf("stats %+v", stats)
	}
	if v := byID(fs)["bearer-label"]; v.Verdict != "likely_fp" || v.VerdictReason == "" {
		t.Fatalf("cached verdict not applied: %+v", v)
	}

	// Lines inserted above move the finding but don't change its code: still free.
	shifted := "// a new comment\n// another\n" + keyFile
	if err := os.WriteFile(filepath.Join(root, "src", "config.ts"), []byte(shifted), 0o644); err != nil {
		t.Fatal(err)
	}
	fs = fixtureFindings()
	fs[1].LineNumber += 2
	if _, err := TriageCodeScan(fs, opts(root, store)); err != nil {
		t.Fatal(err)
	}
	if len(srv.calls) != callsAfterFirst {
		t.Fatal("moving code should not re-triage it")
	}
}

func TestTriageCodeScan_ChangedCodeIsCheckedAgain(t *testing.T) {
	root := writeFixture(t)
	srv := &fakeTriageServer{reply: judgeByEvidence}
	srv.start(t)
	store := openStore(t, root)

	if _, err := TriageCodeScan(fixtureFindings(), opts(root, store)); err != nil {
		t.Fatal(err)
	}
	before := len(srv.calls)

	// Edit the line next to the label finding.
	edited := strings.Replace(labelFile, `email: "Email",`, `email: "Email address",`, 1)
	if err := os.WriteFile(filepath.Join(root, "src", "LoginForm.tsx"), []byte(edited), 0o644); err != nil {
		t.Fatal(err)
	}
	stats, err := TriageCodeScan(fixtureFindings(), opts(root, store))
	if err != nil {
		t.Fatal(err)
	}
	if len(srv.calls) != before+1 {
		t.Fatalf("expected one new triage call, got %d", len(srv.calls)-before)
	}
	last := srv.calls[len(srv.calls)-1]
	if len(last) != 1 || !strings.Contains(last[0].Evidence, `"Password"`) {
		t.Fatalf("only the changed finding should be re-checked: %+v", last)
	}
	if stats.Cached != 1 || stats.Checked != 1 {
		t.Fatalf("stats %+v", stats)
	}
}

func TestTriageCodeScan_FailureLeavesFindingsVisible(t *testing.T) {
	root := writeFixture(t)
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusPaymentRequired)
	}))
	orig := triageURL
	triageURL = srv.URL
	t.Cleanup(func() { triageURL = orig; srv.Close() })
	store := openStore(t, root)

	fs := fixtureFindings()
	stats, err := TriageCodeScan(fs, opts(root, store))
	if err == nil {
		t.Fatal("expected an error")
	}
	if len(fs) != 2 || stats.Hidden != 0 || normalizer.CountHiddenFalseAlarms(fs) != 0 {
		t.Fatalf("a failed check must hide nothing: %+v", stats)
	}
	for _, f := range fs {
		if f.Verdict != "" {
			t.Fatalf("no verdict expected after failure: %+v", f)
		}
	}
	// Nothing was cached, so the next scan tries again.
	if c, _ := store.CachedVerdicts([]string{VerdictCacheKey(fs[0], root)}); len(c) != 0 {
		t.Fatal("failure must not be cached")
	}
}

func TestTriageCodeScan_MemoryOverridesCacheAndAI(t *testing.T) {
	root := writeFixture(t)
	srv := &fakeTriageServer{reply: judgeByEvidence}
	srv.start(t)
	store := openStore(t, root)

	first := fixtureFindings()
	if _, err := TriageCodeScan(first, opts(root, store)); err != nil {
		t.Fatal(err)
	}
	before := len(srv.calls)

	// The user says the hidden one is real, and the shown one is a false alarm.
	if err := store.MarkReal(first[0], memory.SourceUser, "clicked in report"); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkFalseAlarm(first[1], memory.SourceUser, "test key"); err != nil {
		t.Fatal(err)
	}

	fs := fixtureFindings()
	stats, err := TriageCodeScan(fs, opts(root, store))
	if err != nil {
		t.Fatal(err)
	}
	got := byID(fs)
	if got["bearer-label"].Verdict != "confirmed" || got["bearer-label"].VerdictReason != MarkedRealRationale {
		t.Fatalf("marked-real must win over the cached likely_fp: %+v", got["bearer-label"])
	}
	if !got["bearer-key"].HiddenAsFalseAlarm() {
		t.Fatalf("marked false alarm must be hidden: %+v", got["bearer-key"])
	}
	if stats.Memory != 2 || len(srv.calls) != before {
		t.Fatalf("memory decisions must not call the AI: %+v calls=%d", stats, len(srv.calls)-before)
	}

	// Changing their mind flips it back, and the old decision is gone.
	if err := store.MarkFalseAlarm(first[0], memory.SourceUser, ""); err != nil {
		t.Fatal(err)
	}
	fs = fixtureFindings()
	if _, err := TriageCodeScan(fs, opts(root, store)); err != nil {
		t.Fatal(err)
	}
	if !byID(fs)["bearer-label"].HiddenAsFalseAlarm() {
		t.Fatal("latest decision should win")
	}
}

func TestTriageCodeScan_UnsureFalseAlarmStaysVisible(t *testing.T) {
	root := writeFixture(t)
	srv := &fakeTriageServer{reply: func(fs []triageFindingWire, _ int) []Verdict {
		out := make([]Verdict, len(fs))
		for i, f := range fs {
			out[i] = Verdict{ID: f.ID, Verdict: "likely_fp", Confidence: 0.4, Rationale: "probably a label"}
		}
		return out
	}}
	srv.start(t)
	fs := fixtureFindings()
	stats, err := TriageCodeScan(fs, CodeTriageOptions{ProjectRoot: root, AccessToken: "tok"})
	if err != nil {
		t.Fatal(err)
	}
	if stats.Hidden != 0 || fs[0].Verdict != "needs_manual" {
		t.Fatalf("low-confidence false alarm must stay visible: %+v %+v", stats, fs[0])
	}
}

func TestTriageCodeScan_SendsCodeContextForStaticFindings(t *testing.T) {
	root := writeFixture(t)
	srv := &fakeTriageServer{reply: judgeByEvidence}
	srv.start(t)
	fs := fixtureFindings()
	fs[0].SurroundingCode = ExtractEnclosingContext(ResolveFindingFile(root, fs[0].FilePath), fs[0].LineNumber)
	if fs[0].SurroundingCode == "" {
		t.Fatal("expected enclosing context to resolve against the project root")
	}
	if _, err := TriageCodeScan(fs, CodeTriageOptions{ProjectRoot: root, AccessToken: "tok"}); err != nil {
		t.Fatal(err)
	}
	w := srv.calls[0][0]
	if w.MatchedAt != "src/LoginForm.tsx:6" || w.Category != "sast" || w.RuleID == "" ||
		!strings.Contains(w.ResponseSnippet, "labels.password") || w.Rationale == "" {
		t.Fatalf("static finding wire is missing context: %+v", w)
	}
}
