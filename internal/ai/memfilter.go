package ai

import (
	"fmt"
	"strings"

	"github.com/dev-zeph/trojan/internal/memory"
	"github.com/dev-zeph/trojan/internal/normalizer"
)

// FalsePositiveSource is the slice of project memory triage consults before
// spending an AI call. *memory.Store satisfies it; nil disables the filter.
type FalsePositiveSource interface {
	FalsePositives() ([]memory.Event, error)
}

// agenticRuleID is the shared rule id of agent-reported findings; memory keys
// those by title as well, since the rule alone doesn't tell them apart.
const agenticRuleID = "agentic"

// TriageWithMemory is TriageWithContext with memory consulted first: a finding
// the user (or an earlier run) already marked as a false positive is resolved
// locally with a likely_fp verdict and is never sent to the AI. Everything
// else goes through the normal triage path, so a nil source behaves exactly
// like TriageWithContext.
func TriageWithMemory(findings []normalizer.Finding, accessToken string, retriever ContextRetriever, fps FalsePositiveSource) (map[string]Verdict, error) {
	var known []memory.Event
	if fps != nil {
		known, _ = fps.FalsePositives() // memory trouble must never block triage
	}
	verdicts := make(map[string]Verdict)
	rest := make([]normalizer.Finding, 0, len(findings))
	for _, f := range findings {
		if ev, ok := matchFalsePositive(f, known); ok {
			verdicts[f.ID] = Verdict{
				ID:         f.ID,
				Verdict:    "likely_fp",
				Confidence: 1,
				Rationale:  fmt.Sprintf("Previously marked as not a real issue (%s).", ev.At.Format("2006-01-02")),
			}
			continue
		}
		rest = append(rest, f)
	}
	if len(rest) == 0 {
		return verdicts, nil
	}
	got, err := TriageWithContext(rest, accessToken, retriever)
	for id, v := range got {
		verdicts[id] = v
	}
	return verdicts, err
}

// matchFalsePositive finds a recorded false_positive for the same rule on the
// same file (agent findings: same title and URL).
func matchFalsePositive(f normalizer.Finding, known []memory.Event) (memory.Event, bool) {
	file := strings.TrimPrefix(strings.ReplaceAll(f.FilePath, "\\", "/"), "./")
	for _, e := range known {
		if e.Kind != memory.KindFalsePositive || e.File == "" {
			continue
		}
		if !(e.File == file || strings.HasSuffix(file, "/"+e.File)) {
			continue
		}
		if f.RuleID == agenticRuleID {
			if e.RuleID == agenticRuleID+":"+slugTitle(f.Title) {
				return e, true
			}
			continue
		}
		if e.RuleID == f.RuleID {
			return e, true
		}
	}
	return memory.Event{}, false
}

// slugTitle must stay in step with cmd/trojan's slug (lowercase, runs of
// non-alphanumerics collapsed to "-").
func slugTitle(s string) string {
	var b strings.Builder
	dash := false
	for _, r := range strings.ToLower(s) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
			dash = false
		} else if !dash && b.Len() > 0 {
			b.WriteByte('-')
			dash = true
		}
	}
	return strings.TrimSuffix(b.String(), "-")
}
