package scanners

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"

	"github.com/dev-zeph/trojan/internal/normalizer"
)

// Semgrep implements the Scanner interface for static analysis.
type Semgrep struct{}

func (s Semgrep) Name() string     { return "semgrep" }
func (s Semgrep) Category() string { return "sast" }

func (s Semgrep) IsAvailable() bool {
	_, err := exec.LookPath("semgrep")
	return err == nil
}

func (s Semgrep) Run(projectPath string) ([]normalizer.Finding, error) {
	if !s.IsAvailable() {
		return nil, fmt.Errorf("semgrep not found: run 'trojan init' to install it")
	}

	cmd := exec.Command("semgrep", "--config=auto", "--json", projectPath)
	output, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 1 {
			// exit code 1 means findings were found — not a crash
		} else {
			return nil, fmt.Errorf("semgrep failed: %w", err)
		}
	}

	var result semgrepOutput
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, fmt.Errorf("failed to parse semgrep output: %w", err)
	}

	findings := make([]normalizer.Finding, 0, len(result.Results))
	for i, r := range result.Results {
		findings = append(findings, normalizer.Finding{
			ID:          fmt.Sprintf("semgrep-%d", i),
			Scanner:     s.Name(),
			Category:    s.Category(),
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

func ruleIDToTitle(ruleID string) string {
	parts := strings.Split(ruleID, ".")
	if len(parts) == 0 {
		return ruleID
	}
	last := parts[len(parts)-1]
	last = strings.ReplaceAll(last, "-", " ")
	return strings.Title(last)
}
