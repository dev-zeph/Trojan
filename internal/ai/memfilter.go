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

// UserConfirmedSource is optionally implemented by a FalsePositiveSource
// (*memory.Store does): findings a person marked as a real issue. Those win
// over both remembered false alarms and the AI, on every future scan.
type UserConfirmedSource interface {
	UserConfirmed() ([]memory.Event, error)
}

// MarkedRealRationale is the reason shown on a finding a person marked real.
const MarkedRealRationale = "You marked this as a real issue."

// memoryDecisions is what project memory says about findings, loaded once.
type memoryDecisions struct {
	falsePositives []memory.Event
	confirmed      []memory.Event
}

func loadMemoryDecisions(fps FalsePositiveSource) memoryDecisions {
	var d memoryDecisions
	if fps == nil {
		return d
	}
	d.falsePositives, _ = fps.FalsePositives() // memory trouble must never block triage
	if cs, ok := fps.(UserConfirmedSource); ok {
		d.confirmed, _ = cs.UserConfirmed()
	}
	return d
}

// verdictFor returns memory's verdict for a finding, if it has one. A person's
// "this is real" beats a remembered false alarm.
func (d memoryDecisions) verdictFor(f normalizer.Finding) (Verdict, bool) {
	if _, ok := matchEvent(f, d.confirmed, memory.KindConfirmed); ok {
		return Verdict{ID: f.ID, Verdict: "confirmed", Confidence: 1, Rationale: MarkedRealRationale}, true
	}
	if ev, ok := matchEvent(f, d.falsePositives, memory.KindFalsePositive); ok {
		return Verdict{
			ID:         f.ID,
			Verdict:    "likely_fp",
			Confidence: 1,
			Rationale:  fmt.Sprintf("Previously marked as not a real issue (%s).", ev.At.Format("2006-01-02")),
		}, true
	}
	return Verdict{}, false
}

// ApplyMemoryDecisions overwrites the verdict of every finding project memory
// has a decision on. The report server uses it so a "this is a real issue"
// click shows up at once, even on a report reopened from an older scan.
// Returns how many findings changed.
func ApplyMemoryDecisions(findings []normalizer.Finding, fps FalsePositiveSource) int {
	d := loadMemoryDecisions(fps)
	if len(d.confirmed) == 0 && len(d.falsePositives) == 0 {
		return 0
	}
	n := 0
	for i := range findings {
		v, ok := d.verdictFor(findings[i])
		if !ok || (findings[i].Verdict == v.Verdict && findings[i].VerdictReason != "") {
			continue
		}
		findings[i].Verdict, findings[i].VerdictReason, findings[i].VerdictConfidence = v.Verdict, v.Rationale, v.Confidence
		n++
	}
	return n
}

// TriageWithMemory is TriageWithContext with memory consulted first: a finding
// the user (or an earlier run) already marked as a false positive is resolved
// locally with a likely_fp verdict, and one a person marked as a real issue is
// resolved as confirmed; neither is sent to the AI. Everything else goes
// through the normal triage path, so a nil source behaves exactly like
// TriageWithContext.
func TriageWithMemory(findings []normalizer.Finding, accessToken string, retriever ContextRetriever, fps FalsePositiveSource) (map[string]Verdict, error) {
	d := loadMemoryDecisions(fps)
	verdicts := make(map[string]Verdict)
	rest := make([]normalizer.Finding, 0, len(findings))
	for _, f := range findings {
		if v, ok := d.verdictFor(f); ok {
			verdicts[f.ID] = v
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
	return matchEvent(f, known, memory.KindFalsePositive)
}

// matchEvent finds a recorded event of the given kind for the same rule on the
// same file (agent findings: same title and URL).
func matchEvent(f normalizer.Finding, known []memory.Event, kind memory.Kind) (memory.Event, bool) {
	file := strings.TrimPrefix(strings.ReplaceAll(f.FilePath, "\\", "/"), "./")
	for _, e := range known {
		if e.Kind != kind || e.File == "" {
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
