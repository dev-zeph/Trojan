package scanners

import (
	"encoding/json"
	"fmt"
	"os/exec"

	"github.com/dev-zeph/trojan/internal/normalizer"
)

// Checkov implements the Scanner interface for IaC misconfiguration scanning.
type Checkov struct{}

func (c Checkov) Name() string     { return "checkov" }
func (c Checkov) Category() string { return "iac" }

func (c Checkov) IsAvailable() bool {
	return IsInstalled("checkov")
}

func (c Checkov) Run(projectPath string) ([]normalizer.Finding, error) {
	if !c.IsAvailable() {
		return nil, fmt.Errorf("checkov not found: run 'trojan init' to install it")
	}

	cmd := exec.Command(ManagedBinary("checkov"), "-d", projectPath, "-o", "json", "--quiet")
	output, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 1 {
			// findings found
		} else {
			return nil, fmt.Errorf("checkov failed: %w", err)
		}
	}

	// Checkov can return either a single object or an array
	// Try array first, fall back to single object
	var results []checkovOutput
	if err := json.Unmarshal(output, &results); err != nil {
		var single checkovOutput
		if err2 := json.Unmarshal(output, &single); err2 != nil {
			return nil, fmt.Errorf("failed to parse checkov output: %w", err)
		}
		results = []checkovOutput{single}
	}

	findings := []normalizer.Finding{}
	idx := 0
	for _, result := range results {
		for _, check := range result.Results.FailedChecks {
			findings = append(findings, normalizer.Finding{
				ID:         fmt.Sprintf("checkov-%d", idx),
				Scanner:    c.Name(),
				Category:   c.Category(),
				Severity:   normalizer.SeverityMedium,
				Title:      check.CheckName,
				RawMessage: fmt.Sprintf("%s failed for resource %s", check.CheckID, check.Resource),
				FilePath:   check.Repo,
				LineNumber: check.FileLineRange[0],
				RuleID:     check.CheckID,
				Status:     normalizer.StatusOpen,
			})
			idx++
		}
	}

	return findings, nil
}

type checkovOutput struct {
	Results struct {
		FailedChecks []struct {
			CheckID       string `json:"check_id"`
			CheckName     string `json:"check_name"`
			Resource      string `json:"resource"`
			Repo          string `json:"repo_file_path"`
			FileLineRange []int  `json:"file_line_range"`
		} `json:"failed_checks"`
	} `json:"results"`
}
