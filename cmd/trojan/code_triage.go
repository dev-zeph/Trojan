package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/fatih/color"

	"github.com/dev-zeph/trojan/internal/ai"
	"github.com/dev-zeph/trojan/internal/config"
	"github.com/dev-zeph/trojan/internal/memory"
	"github.com/dev-zeph/trojan/internal/normalizer"
)

// codeTriage is the code-scan AI false-alarm check, injectable for tests.
var codeTriage = ai.TriageCodeScan

// triageCodeFindings runs the AI false-alarm check over every finding of a
// code scan (after the scanners, before AI explanations and the report) and
// writes each verdict onto its finding. Likely false alarms are then hidden
// from the report's list and score, but kept in the stored result.
//
// It never drops a finding: when the check fails, whatever it could not reach
// stays visible and the returned note says why, for the report to show.
func triageCodeFindings(projectPath string, findings []normalizer.Finding, accessToken string) (note string) {
	if len(findings) == 0 || accessToken == "" {
		return ""
	}

	fmt.Printf("  → Double-checking %d finding(s) for false alarms...\n", len(findings))

	opts := ai.CodeTriageOptions{
		ProjectRoot: projectPath,
		AccessToken: accessToken,
		Retriever:   loadRetriever(projectPath, accessToken),
	}
	if store, err := memory.Open(projectPath); err == nil {
		defer store.Close()
		opts.Memory = store
		opts.Cache = store
	} else {
		fmt.Fprintf(os.Stderr, "trojan: could not open project memory (%s); checking without the cache\n", err)
	}

	stats, err := codeTriage(findings, opts)
	if stats.Cached+stats.Memory > 0 {
		fmt.Printf("    %d already checked on an earlier scan (no tokens used)\n", stats.Cached+stats.Memory)
	}
	if err != nil {
		note = triageFailureNote(err)
		color.Yellow("  %s\n", note)
	}
	if stats.Hidden > 0 {
		fmt.Printf("  → Trojan hid %d false alarm%s. See them in the report.\n", stats.Hidden, triagePlural(stats.Hidden))
	}
	return note
}

// scanOnceTriage is the false-alarm check for scans started by an AI tool over
// MCP (run_scan): same check, same cache, when the user is signed in.
func scanOnceTriage(projectPath string, findings []normalizer.Finding) string {
	cfg, err := config.LoadConfig()
	if err != nil || cfg.AccessToken == "" {
		return ""
	}
	for i := range findings {
		findings[i].SurroundingCode = ai.ExtractEnclosingContext(ai.ResolveFindingFile(projectPath, findings[i].FilePath), findings[i].LineNumber)
	}
	return triageCodeFindings(projectPath, findings, cfg.AccessToken)
}

// triageFailureNote turns a triage error into one plain sentence.
func triageFailureNote(err error) string {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "rate_limit"):
		return "Trojan couldn't double-check every finding for false alarms today (daily AI limit reached), so some may be false alarms."
	case strings.Contains(msg, "402"):
		return "Trojan couldn't double-check every finding for false alarms (out of Trojan Tokens), so some may be false alarms."
	default:
		return "Trojan couldn't double-check every finding for false alarms, so some may be false alarms."
	}
}

// visibleSeverityCounts counts findings by severity, leaving out the ones
// hidden as likely false alarms.
func visibleSeverityCounts(findings []normalizer.Finding) map[string]int {
	counts := map[string]int{}
	for _, f := range findings {
		if !f.HiddenAsFalseAlarm() {
			counts[string(f.Severity)]++
		}
	}
	return counts
}

func triagePlural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}
