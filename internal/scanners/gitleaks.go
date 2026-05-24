package scanners

import (
	"encoding/json"
	"fmt"
	"os/exec"

	"github.com/dev-zeph/trojan/internal/normalizer"
)

// Gitleaks implements the Scanner interface for secrets detection.
type Gitleaks struct{}

func (g Gitleaks) Name() string     { return "gitleaks" }
func (g Gitleaks) Category() string { return "secrets" }

func (g Gitleaks) IsAvailable() bool {
	_, err := exec.LookPath("gitleaks")
	return err == nil
}

func (g Gitleaks) Run(projectPath string) ([]normalizer.Finding, error) {
	if !g.IsAvailable() {
		return nil, fmt.Errorf("gitleaks not found: run 'trojan init' to install it")
	}

	cmd := exec.Command("gitleaks", "detect", "--source", projectPath, "--report-format", "json", "--report-path", "/dev/stdout", "--no-banner", "-q")
	output, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 1 {
			// exit code 1 means secrets found
		} else {
			return nil, fmt.Errorf("gitleaks failed: %w", err)
		}
	}

	if len(output) == 0 {
		return []normalizer.Finding{}, nil
	}

	var results []gitleaksResult
	if err := json.Unmarshal(output, &results); err != nil {
		return nil, fmt.Errorf("failed to parse gitleaks output: %w", err)
	}

	findings := make([]normalizer.Finding, 0, len(results))
	for i, r := range results {
		findings = append(findings, normalizer.Finding{
			ID:          fmt.Sprintf("gitleaks-%d", i),
			Scanner:     g.Name(),
			Category:    g.Category(),
			Severity:    normalizer.SeverityHigh, // secrets are always high severity
			Title:       fmt.Sprintf("Leaked %s", r.Description),
			RawMessage:  fmt.Sprintf("Secret detected in commit %s", r.Commit),
			FilePath:    r.File,
			LineNumber:  r.StartLine,
			CodeSnippet: r.Match,
			RuleID:      r.RuleID,
			Status:      normalizer.StatusOpen,
		})
	}

	return findings, nil
}

type gitleaksResult struct {
	Description string `json:"Description"`
	StartLine   int    `json:"StartLine"`
	Match       string `json:"Match"`
	File        string `json:"File"`
	Commit      string `json:"Commit"`
	RuleID      string `json:"RuleID"`
}
