package scanners

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/dev-zeph/trojan/internal/normalizer"
)

// Nuclei implements DastScanner using the Nuclei v3 vulnerability scanner.
type Nuclei struct{}

func (n Nuclei) Name() string     { return "nuclei" }
func (n Nuclei) Category() string { return "dast" }

func (n Nuclei) IsAvailable() bool {
	return IsInstalled("nuclei")
}

func (n Nuclei) Run(targetURL string) ([]normalizer.Finding, error) {
	if !n.IsAvailable() {
		return nil, fmt.Errorf("nuclei not found: run 'trojan dast' to install it")
	}

	// Write findings to a temp file so nuclei sees a real TTY on stdout/stderr
	// and shows its progress output. If we pipe stdout, nuclei detects non-TTY
	// and suppresses all progress — the terminal appears completely frozen.
	outFile, err := os.CreateTemp("", "trojan-nuclei-*.jsonl")
	if err != nil {
		return nil, fmt.Errorf("nuclei: could not create temp file: %w", err)
	}
	outPath := outFile.Name()
	outFile.Close()
	defer os.Remove(outPath)

	cmd := exec.Command(
		ManagedBinary("nuclei"),
		"-target", targetURL,
		"-output", outPath,          // findings → temp file (not stdout)
		"-jsonl",                    // JSONL format in the output file
		"-severity", "critical,high,medium,low",
		"-ni",                       // skip OOB/interactsh (not useful locally)
	)
	// stdout and stderr both go to the user's terminal — full progress visible.
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	// Run blocks until the scan finishes. All nuclei output streams to the terminal.
	cmd.Run() //nolint:errcheck — nuclei exits non-zero even when findings exist

	// Parse the output file.
	data, err := os.ReadFile(outPath)
	if err != nil || len(data) == 0 {
		return nil, nil
	}

	var findings []normalizer.Finding
	idx := 0

	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		var result nucleiResult
		if err := json.Unmarshal([]byte(line), &result); err != nil {
			continue
		}

		title := result.Info.Name
		if result.MatcherName != "" {
			title = fmt.Sprintf("%s — %s", result.Info.Name, result.MatcherName)
		}

		findings = append(findings, normalizer.Finding{
			ID:          fmt.Sprintf("nuclei-%d", idx),
			Scanner:     n.Name(),
			Category:    n.Category(),
			Severity:    normalizeNucleiSeverity(result.Info.Severity),
			Title:       title,
			RawMessage:  result.Info.Description,
			FilePath:    result.MatchedAt,
			LineNumber:  0,
			RuleID:      result.TemplateID,
			CodeSnippet: buildRequestSnippet(result.Request),
			Status:      normalizer.StatusOpen,
		})
		idx++
	}

	return findings, nil
}

// buildRequestSnippet returns the first 8 lines of an HTTP request string,
// trimmed to fit neatly in the code snippet pane.
func buildRequestSnippet(request string) string {
	if request == "" {
		return ""
	}
	lines := strings.Split(request, "\n")
	if len(lines) > 8 {
		lines = lines[:8]
		lines = append(lines, "...")
	}
	return strings.Join(lines, "\n")
}

// nucleiResult maps the fields we care about from Nuclei's NDJSON output.
type nucleiResult struct {
	TemplateID  string `json:"template-id"`
	Info        struct {
		Name        string `json:"name"`
		Severity    string `json:"severity"`
		Description string `json:"description"`
	} `json:"info"`
	MatcherName string `json:"matcher-name"`
	MatchedAt   string `json:"matched-at"`
	Request     string `json:"request"`
}

func normalizeNucleiSeverity(s string) normalizer.Severity {
	switch strings.ToLower(s) {
	case "critical":
		return normalizer.SeverityCritical
	case "high":
		return normalizer.SeverityHigh
	case "medium":
		return normalizer.SeverityMedium
	case "low":
		return normalizer.SeverityLow
	default:
		return normalizer.SeverityInfo
	}
}
