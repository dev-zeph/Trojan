package ai

import (
	"strings"
	"testing"
	"time"

	"github.com/dev-zeph/trojan/internal/memory"
	"github.com/dev-zeph/trojan/internal/normalizer"
)

type fakeFPs struct{ events []memory.Event }

func (f fakeFPs) FalsePositives() ([]memory.Event, error) { return f.events, nil }

func TestTriageWithMemory_SkipsKnownFalsePositives(t *testing.T) {
	var sent []string
	orig := triageImpl
	triageImpl = func(fs []normalizer.Finding, _ string) (map[string]Verdict, error) {
		out := map[string]Verdict{}
		for _, f := range fs {
			sent = append(sent, f.ID)
			out[f.ID] = Verdict{ID: f.ID, Verdict: "confirmed", Confidence: 0.9}
		}
		return out, nil
	}
	defer func() { triageImpl = orig }()

	at := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	fps := fakeFPs{events: []memory.Event{
		{Kind: memory.KindFalsePositive, File: "src/a.go", RuleID: "go-sqli", Title: "sqli", At: at},
		{Kind: memory.KindFalsePositive, File: "http://x.test/api/ping", RuleID: "agentic:verbose-error", Title: "Verbose error", At: at},
	}}
	findings := []normalizer.Finding{
		{ID: "fp-scan", RuleID: "go-sqli", FilePath: "/home/me/proj/src/a.go"},
		{ID: "real-scan", RuleID: "go-sqli", FilePath: "/home/me/proj/src/b.go"},
		{ID: "fp-agent", RuleID: "agentic", Title: "Verbose error", FilePath: "http://x.test/api/ping"},
		{ID: "other-agent", RuleID: "agentic", Title: "IDOR on orders", FilePath: "http://x.test/api/ping"},
	}

	v, err := TriageWithMemory(findings, "tok", nil, fps)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"fp-scan", "fp-agent"} {
		got := v[id]
		if got.Verdict != "likely_fp" || !strings.Contains(got.Rationale, "Previously marked as not a real issue") || !strings.Contains(got.Rationale, "2026-10-01") {
			t.Errorf("%s verdict = %+v", id, got)
		}
	}
	if len(sent) != 2 || sent[0] != "real-scan" || sent[1] != "other-agent" {
		t.Errorf("AI got %v, want only [real-scan other-agent]", sent)
	}
	if v["real-scan"].Verdict != "confirmed" {
		t.Errorf("others must still be triaged: %+v", v["real-scan"])
	}
}

func TestTriageWithMemory_AllKnownMakesNoAICall(t *testing.T) {
	calls := 0
	orig := triageImpl
	triageImpl = func([]normalizer.Finding, string) (map[string]Verdict, error) {
		calls++
		return nil, nil
	}
	defer func() { triageImpl = orig }()

	fps := fakeFPs{events: []memory.Event{{Kind: memory.KindFalsePositive, File: "a.go", RuleID: "r", At: time.Now()}}}
	v, err := TriageWithMemory([]normalizer.Finding{{ID: "1", RuleID: "r", FilePath: "a.go"}}, "tok", nil, fps)
	if err != nil || calls != 0 || v["1"].Verdict != "likely_fp" {
		t.Errorf("calls=%d err=%v verdict=%+v", calls, err, v["1"])
	}
}

func TestTriageWithMemory_NilSourceIsPlainTriage(t *testing.T) {
	calls := 0
	orig := triageImpl
	triageImpl = func(fs []normalizer.Finding, _ string) (map[string]Verdict, error) {
		calls++
		return map[string]Verdict{fs[0].ID: {ID: fs[0].ID, Verdict: "confirmed", Confidence: 1}}, nil
	}
	defer func() { triageImpl = orig }()

	v, _ := TriageWithMemory([]normalizer.Finding{{ID: "1"}}, "tok", nil, nil)
	if calls != 1 || v["1"].Verdict != "confirmed" {
		t.Errorf("calls=%d v=%+v", calls, v)
	}
}
