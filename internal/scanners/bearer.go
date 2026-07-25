package scanners

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"

	"github.com/dev-zeph/trojan/internal/normalizer"
)

// Bearer implements the Scanner interface for SAST using Bearer CLI.
// Acts as a standalone-binary SAST scanner alongside Semgrep.
type Bearer struct{}

func (b Bearer) Name() string     { return "bearer" }
func (b Bearer) Category() string { return "sast" }

func (b Bearer) IsAvailable() bool {
	return IsInstalled("bearer")
}

func (b Bearer) Run(projectPath string) ([]normalizer.Finding, error) {
	if !b.IsAvailable() {
		return nil, fmt.Errorf("bearer not found: run 'trojan init' to install it")
	}

	args := []string{
		"scan",
		"--format", "json",
		"--quiet",
		"--skip-path", "node_modules",
		"--skip-path", "vendor",
		"--skip-path", "dist",
		"--skip-path", "build",
		"--skip-path", ".next",
		"--skip-path", "__pycache__",
		"--skip-path", "coverage",
		projectPath,
	}
	cmd := exec.Command(ManagedBinary("bearer"), args...)
	output, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 1 {
			// exit code 1 means findings were found — not a crash; stdout has JSON
		} else {
			return nil, fmt.Errorf("bearer failed: %w", err)
		}
	}

	// Bearer groups findings by severity: {"critical": [...], "high": [...], ...}
	var result map[string][]bearerFinding
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, fmt.Errorf("failed to parse bearer output: %w", err)
	}

	var findings []normalizer.Finding
	i := 0
	for severity, items := range result {
		for _, f := range items {
			// Prefix CWE IDs with "CWE-" if they're bare numbers.
			cweIDs := make([]string, 0, len(f.CWEIDs))
			for _, id := range f.CWEIDs {
				if !strings.HasPrefix(id, "CWE-") {
					id = "CWE-" + id
				}
				cweIDs = append(cweIDs, id)
			}
			findings = append(findings, normalizer.Finding{
				ID:          fmt.Sprintf("bearer-%d", i),
				Scanner:     b.Name(),
				Category:    b.Category(),
				Severity:    normalizeBearerSeverity(severity),
				Title:       f.Title,
				RawMessage:  f.Description,
				FilePath:    f.Filename,
				LineNumber:  f.LineNumber,
				CodeSnippet: strings.TrimSpace(f.CodeExtract),
				RuleID:      f.ID,
				Status:      normalizer.StatusOpen,
				CWEIDs:      cweIDs,
			})
			i++
		}
	}

	return findings, nil
}

// bearerFinding matches the JSON structure of a single Bearer finding.
type bearerFinding struct {
	ID             string   `json:"id"`
	Title          string   `json:"title"`
	Description    string   `json:"description"`
	CWEIDs         []string `json:"cwe_ids"`
	Filename       string   `json:"filename"`
	FullFilename   string   `json:"full_filename"`
	LineNumber     int      `json:"line_number"`
	CodeExtract    string   `json:"code_extract"`
	DocURL         string   `json:"documentation_url"`
	Fingerprint    string   `json:"fingerprint"`
	CategoryGroups []string `json:"category_groups"`
	Source         struct {
		Start  int `json:"start"`
		End    int `json:"end"`
		Column struct {
			Start int `json:"start"`
			End   int `json:"end"`
		} `json:"column"`
	} `json:"source"`
}

func normalizeBearerSeverity(s string) normalizer.Severity {
	switch strings.ToLower(s) {
	case "critical":
		return normalizer.SeverityCritical
	case "high":
		return normalizer.SeverityHigh
	case "medium":
		return normalizer.SeverityMedium
	case "low":
		return normalizer.SeverityLow
	case "warning":
		return normalizer.SeverityInfo
	default:
		return normalizer.SeverityLow
	}
}
