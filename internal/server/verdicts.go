package server

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/dev-zeph/trojan/internal/ai"
	"github.com/dev-zeph/trojan/internal/memory"
	"github.com/dev-zeph/trojan/internal/normalizer"
)

// ── False-alarm decisions from the report ────────────────────────────────────
//
// The report hides findings the AI check judged likely false alarms, behind a
// "Trojan hid N false alarms" list. From that list (or a shown finding) the
// user can say "this is a real issue" or "this is a false alarm". The decision
// is saved in the project's memory (.trojan/memory.db), so every later scan
// honors it, and it is applied to the report right away.

// falseAlarmReason is shown on a finding the user marked as a false alarm.
const falseAlarmReason = "You marked this as a false alarm."

// projectMemoryDir returns the project folder of a code scan, or "" when the
// scan isn't of a local folder (a website test's ProjectPath is a URL).
func projectMemoryDir(projectPath string) string {
	if projectPath == "" {
		return ""
	}
	if info, err := os.Stat(projectPath); err != nil || !info.IsDir() {
		return ""
	}
	return projectPath
}

// recordDecision saves the user's verdict on a finding in project memory.
func recordDecision(projectPath string, f normalizer.Finding, real bool) error {
	dir := projectMemoryDir(projectPath)
	if dir == "" {
		return fmt.Errorf("not a project folder")
	}
	store, err := memory.Open(dir)
	if err != nil {
		return err
	}
	defer store.Close()
	if real {
		return store.MarkReal(f, memory.SourceUser, "marked as a real issue in the Trojan report")
	}
	return store.MarkFalseAlarm(f, memory.SourceUser, "marked as a false alarm in the Trojan report")
}

// applyDecision sets the verdict on the in-memory finding to match.
func applyDecision(f *normalizer.Finding, real bool) {
	if real {
		f.Verdict, f.VerdictReason, f.VerdictConfidence = "confirmed", ai.MarkedRealRationale, 1
		return
	}
	f.Verdict, f.VerdictReason, f.VerdictConfidence = normalizer.VerdictLikelyFP, falseAlarmReason, 1
}

// withMemoryDecisions returns a copy of findings with project memory's
// decisions applied, so a report reopened from an older scan still reflects
// what the user decided since. Without a memory file it returns findings as is
// (and never creates one).
func withMemoryDecisions(projectPath string, findings []normalizer.Finding) []normalizer.Finding {
	dir := projectMemoryDir(projectPath)
	if dir == "" {
		return findings
	}
	if _, err := os.Stat(filepath.Join(dir, filepath.FromSlash(memory.DefaultDBPath))); err != nil {
		return findings
	}
	store, err := memory.Open(dir)
	if err != nil {
		return findings
	}
	defer store.Close()
	out := make([]normalizer.Finding, len(findings))
	copy(out, findings)
	ai.ApplyMemoryDecisions(out, store)
	return out
}
