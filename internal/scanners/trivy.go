package scanners

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"

	"github.com/dev-zeph/trojan/internal/normalizer"
)

// Trivy implements the Scanner interface for SCA (dependency vulnerability scanning).
type Trivy struct{}

func (t Trivy) Name() string     { return "trivy" }
func (t Trivy) Category() string { return "sca" }

func (t Trivy) IsAvailable() bool {
	_, err := exec.LookPath("trivy")
	return err == nil
}

func (t Trivy) Run(projectPath string) ([]normalizer.Finding, error) {
	if !t.IsAvailable() {
		return nil, fmt.Errorf("trivy not found: run 'trojan init' to install it")
	}

	cmd := exec.Command("trivy", "fs", "--format", "json", "--quiet", projectPath)
	output, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 1 {
			// findings found
		} else {
			return nil, fmt.Errorf("trivy failed: %w", err)
		}
	}

	var result trivyOutput
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, fmt.Errorf("failed to parse trivy output: %w", err)
	}

	findings := []normalizer.Finding{}
	idx := 0
	for _, res := range result.Results {
		for _, vuln := range res.Vulnerabilities {
			findings = append(findings, normalizer.Finding{
				ID:         fmt.Sprintf("trivy-%d", idx),
				Scanner:    t.Name(),
				Category:   t.Category(),
				Severity:   normalizeTrivySeverity(vuln.Severity),
				Title:      fmt.Sprintf("%s in %s", vuln.VulnerabilityID, vuln.PkgName),
				RawMessage: vuln.Description,
				FilePath:   res.Target,
				LineNumber: 0,
				RuleID:     vuln.VulnerabilityID,
				Status:     normalizer.StatusOpen,
			})
			idx++
		}
	}

	return findings, nil
}

type trivyOutput struct {
	Results []struct {
		Target          string `json:"Target"`
		Vulnerabilities []struct {
			VulnerabilityID string `json:"VulnerabilityID"`
			PkgName         string `json:"PkgName"`
			Severity        string `json:"Severity"`
			Description     string `json:"Description"`
		} `json:"Vulnerabilities"`
	} `json:"Results"`
}

func normalizeTrivySeverity(s string) normalizer.Severity {
	switch strings.ToUpper(s) {
	case "CRITICAL":
		return normalizer.SeverityCritical
	case "HIGH":
		return normalizer.SeverityHigh
	case "MEDIUM":
		return normalizer.SeverityMedium
	case "LOW":
		return normalizer.SeverityLow
	default:
		return normalizer.SeverityInfo
	}
}
