package mcpserver

import (
	"fmt"
	"os"
	"strings"

	"github.com/dev-zeph/trojan/internal/memory"
	"github.com/dev-zeph/trojan/internal/normalizer"
)

// ── Memory wiring for the finding tools ──────────────────────────────────────
//
// mark_fixed, suppress_finding and verify_fix record what the user decided
// in the project's memory (.trojan/memory.db), so the next scan, triage and
// the pen-test agent know it. get_findings reads it back to hide findings the
// user already dismissed as false alarms. Memory failures never fail a tool:
// the status change in the scan file is what the user asked for.

// suppressKind maps a suppress_finding reason to a memory kind. Kept simple
// on purpose: a reason saying the user accepts it ("user accepts the risk",
// "accepted") is an accepted risk; anything else, including no reason, is a
// false alarm.
func suppressKind(reason string) memory.Kind {
	if strings.Contains(strings.ToLower(reason), "accept") {
		return memory.KindAcceptedRisk
	}
	return memory.KindFalsePositive
}

// recordStatusMemory records a mark_fixed or suppress_finding decision.
func recordStatusMemory(projectPath string, f normalizer.Finding, status normalizer.Status, reason string) {
	var kind memory.Kind
	evidence := strings.TrimSpace(reason)
	switch status {
	case normalizer.StatusResolved:
		kind = memory.KindFixed
		if evidence == "" {
			evidence = "marked fixed through the MCP server without a re-check"
		}
	case normalizer.StatusSuppressed:
		kind = suppressKind(reason)
		if evidence == "" {
			evidence = "suppressed through the MCP server"
		}
	default:
		return
	}
	recordMemory(projectPath, f, kind, evidence)
}

// recordMemory writes one event about a finding, keyed to its graph node
// when the scan placed it.
func recordMemory(projectPath string, f normalizer.Finding, kind memory.Kind, evidence string) {
	store, err := memory.Open(projectPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "trojan: could not open memory: %s\n", err)
		return
	}
	defer store.Close()
	e := memory.EventFromFinding(f, kind, memory.SourceClaude, projectPath)
	e.Evidence = evidence
	if f.Reach != nil {
		e.NodeKey = f.Reach.NodeKey
	}
	if err := store.Record(e); err != nil {
		fmt.Fprintf(os.Stderr, "trojan: could not record memory: %s\n", err)
	}
}

// rememberedFalsePositives returns a predicate for findings memory marks as
// false positives. With include set (or no memory yet) nothing is hidden.
func rememberedFalsePositives(projectPath string, include bool) func(normalizer.Finding) bool {
	none := func(normalizer.Finding) bool { return false }
	if include || !hasMemory(projectPath) {
		return none
	}
	store, err := memory.Open(projectPath)
	if err != nil {
		return none
	}
	fps, err := store.FalsePositives()
	store.Close()
	if err != nil || len(fps) == 0 {
		return none
	}
	type key struct{ rule, file string }
	set := map[key]bool{}
	for _, e := range fps {
		set[key{e.RuleID, e.File}] = true
	}
	return func(f normalizer.Finding) bool {
		e := memory.EventFromFinding(f, memory.KindFalsePositive, memory.SourceClaude, projectPath)
		return set[key{e.RuleID, e.File}]
	}
}

// exposureSummary renders a finding's reach in a few words for get_findings:
// "public route, no login check, writes orders".
func exposureSummary(r *normalizer.ReachInfo) string {
	var parts []string
	switch {
	case r.ClientSide:
		parts = append(parts, "runs in the browser")
	case r.Reachable && !r.Guarded:
		parts = append(parts, "public route, no login check")
	case r.Reachable:
		parts = append(parts, "behind login")
	default:
		parts = append(parts, "not reached from a route")
	}
	if len(r.Writes) > 0 {
		parts = append(parts, "writes "+strings.Join(capN(r.Writes, 3), ", "))
	}
	if len(r.Reads) > 0 {
		parts = append(parts, "reads "+strings.Join(capN(r.Reads, 3), ", "))
	}
	if r.Sensitive {
		parts = append(parts, "sensitive data")
	}
	return strings.Join(parts, "; ")
}
