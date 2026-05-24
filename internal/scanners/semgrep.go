package scanners

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"

	"github.com/dev-zeph/trojan/internal/normalizer"
)

// semgrepOutput matches the JSON structure that Semgrep produces.
type semgrepOutput struct {
	Results []semgrepResult `json:"results"`
	Errors  []struct {
		Message string `json:"message"`
	} `json:"errors"`
}

type semgrepResult struct {
	CheckID string `json:"check_id"`
	Path    string `json:"path"`
	Start   struct {
		Line int `json:"line"`
	} `json:"start"`
	Extra struct {
		Message  string `json:"message"`
		Severity string `json:"severity"`
		Lines    string `json:"lines"`
	} `json:"extra"`
}

// RunSemgrep runs Semgrep on the given project path and returns normalized findings.
func RunSemgrep(projectPath string) ([]normalizer.Finding, error) {
	// Check Semgrep is installed
	if _, err := exec.LookPath("semgrep"); err != nil {
		return nil, fmt.Errorf("semgrep not found: run 'trojan init' to install it")
	}

	// Run semgrep and capture JSON output
	cmd := exec.Command("semgrep", "--config=auto", "--json", projectPath)
	output, err := cmd.Output()
	if err != nil {
		// Semgrep exits with code 1 when it finds issues — that's expected, not an error
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 1 {
			// findings were found, output still contains valid JSON
		} else {
			return nil, fmt.Errorf("semgrep failed: %w", err)
		}
	}

	// Parse JSON output
	var result semgrepOutput
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, fmt.Errorf("failed to parse semgrep output: %w", err)
	}

	// Normalize into Finding structs
	findings := make([]normalizer.Finding, 0, len(result.Results))
	for i, r := range result.Results {
		findings = append(findings, normalizer.Finding{
			ID:          fmt.Sprintf("semgrep-%d", i),
			Scanner:     "semgrep",
			Category:    "sast",
			Severity:    normalizeSemgrepSeverity(r.Extra.Severity),
			Title:       ruleIDToTitle(r.CheckID),
			RawMessage:  r.Extra.Message,
			FilePath:    r.Path,
			LineNumber:  r.Start.Line,
			CodeSnippet: strings.TrimSpace(r.Extra.Lines),
			RuleID:      r.CheckID,
			Status:      normalizer.StatusOpen,
		})
	}

	return findings, nil
}

// normalizeSemgrepSeverity maps Semgrep's severity strings to our Severity type.
func normalizeSemgrepSeverity(s string) normalizer.Severity {
	switch strings.ToUpper(s) {
	case "ERROR":
		return normalizer.SeverityHigh
	case "WARNING":
		return normalizer.SeverityMedium
	case "INFO":
		return normalizer.SeverityInfo
	default:
		return normalizer.SeverityLow
	}
}

// ruleIDToTitle converts a rule ID like "python.lang.security.sql-injection"
// into a readable title like "SQL Injection".
func ruleIDToTitle(ruleID string) string {
	parts := strings.Split(ruleID, ".")
	if len(parts) == 0 {
		return ruleID
	}
	last := parts[len(parts)-1]
	last = strings.ReplaceAll(last, "-", " ")
	return strings.Title(last)
}
