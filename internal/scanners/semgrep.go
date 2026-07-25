package scanners

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"runtime"
	"strings"

	"github.com/dev-zeph/trojan/internal/normalizer"
)

// Semgrep implements the Scanner interface for static analysis.
type Semgrep struct{}

func (s Semgrep) Name() string     { return "semgrep" }
func (s Semgrep) Category() string { return "sast" }

func (s Semgrep) IsAvailable() bool {
	return IsInstalled("semgrep")
}

func (s Semgrep) Run(projectPath string) ([]normalizer.Finding, error) {
	if !s.IsAvailable() {
		return nil, fmt.Errorf("semgrep not found: run 'trojan init' to install it")
	}

	// Build args: parallel jobs + skip generated/vendor dirs + cap large files.
	args := []string{
		"--config=auto",
		"--json",
		"--jobs", fmt.Sprintf("%d", runtime.NumCPU()),
		"--max-target-bytes", "1000000", // skip files > 1MB (minified JS, generated code)
		// Exclude directories that are not source code.
		"--exclude", "node_modules",
		"--exclude", "vendor",
		"--exclude", "dist",
		"--exclude", "build",
		"--exclude", ".next",
		"--exclude", "__pycache__",
		"--exclude", "coverage",
		"--exclude", "*.min.js",
		projectPath,
	}
	cmd := exec.Command(ManagedBinary("semgrep"), args...)
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
			CWEIDs:      parseCWEIDs(r.Extra.Metadata.CWE),
			OWASP:       r.Extra.Metadata.OWASP,
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
		Metadata struct {
			CWE   []string `json:"cwe"`
			OWASP []string `json:"owasp"`
		} `json:"metadata"`
	} `json:"extra"`
}

// parseCWEIDs extracts CWE numbers from strings like "CWE-79: Cross-site Scripting".
func parseCWEIDs(raw []string) []string {
	var ids []string
	for _, s := range raw {
		// Take everything before the colon: "CWE-79: ..." → "CWE-79"
		if idx := strings.Index(s, ":"); idx > 0 {
			ids = append(ids, strings.TrimSpace(s[:idx]))
		} else {
			ids = append(ids, strings.TrimSpace(s))
		}
	}
	return ids
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
