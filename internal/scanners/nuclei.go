package scanners

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"

	"github.com/dev-zeph/trojan/internal/normalizer"
)

// Running Nuclei scans are tracked so the CLI's signal handler can force-kill
// them (and their process groups) the instant a desktop scan is cancelled —
// otherwise killing the sidecar orphans Nuclei and it keeps hammering the target.
var (
	dastProcMu sync.Mutex
	dastProcs  = map[int]*os.Process{}
)

func registerDastProc(p *os.Process) {
	if p == nil {
		return
	}
	dastProcMu.Lock()
	dastProcs[p.Pid] = p
	dastProcMu.Unlock()
}

func unregisterDastProc(p *os.Process) {
	if p == nil {
		return
	}
	dastProcMu.Lock()
	delete(dastProcs, p.Pid)
	dastProcMu.Unlock()
}

// TerminateDastScans force-kills every in-flight Nuclei scan and its process
// group. Called from the CLI signal handler on cancel/Ctrl+C.
func TerminateDastScans() {
	dastProcMu.Lock()
	defer dastProcMu.Unlock()
	for pid, p := range dastProcs {
		// killProcessTree is platform-specific: process-group kill on Unix,
		// taskkill /T on Windows (see procgroup_{unix,windows}.go).
		killProcessTree(p)
		delete(dastProcs, pid)
	}
}

// Nuclei implements DastScanner using the Nuclei v3 vulnerability scanner.
type Nuclei struct {
	// ExtraTemplateDirs are directories containing AI-generated Nuclei YAML
	// templates that are appended to the scan alongside the standard templates.
	ExtraTemplateDirs []string
}

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

	args := []string{
		"-target", targetURL,
		"-output", outPath,         // findings → temp file (not stdout)
		"-jsonl",                   // JSONL format in the output file
		"-severity", "critical,high,medium,low",
		"-ni",                      // skip OOB/interactsh (not useful locally)
	}

	// When extra (AI-generated) template dirs are specified, Nuclei treats any
	// -t flag as overriding the default templates directory — so we must also
	// include the default nuclei-templates dir explicitly to keep the standard
	// 6,618 template scan alongside the custom ones.
	if len(n.ExtraTemplateDirs) > 0 {
		home, _ := os.UserHomeDir()
		defaultTemplates := filepath.Join(home, "nuclei-templates")
		if info, err := os.Stat(defaultTemplates); err == nil && info.IsDir() {
			args = append(args, "-t", defaultTemplates)
		}
		for _, dir := range n.ExtraTemplateDirs {
			args = append(args, "-t", dir)
		}
	}

	cmd := exec.Command(ManagedBinary("nuclei"), args...)
	// Nuclei progress (spinner, stats) goes to stderr — keep that on the terminal.
	// Stdout gets the matched-result JSONL which we capture in outPath; discarding
	// it here prevents the raw JSON blobs from flooding the user's terminal.
	cmd.Stdout = io.Discard
	cmd.Stderr = os.Stderr
	// Own process group so TerminateDastScans can kill Nuclei (and any child it
	// spawns) as a group on cancel, rather than orphaning it. Platform-specific.
	setProcGroup(cmd)

	// Start + register + Wait (instead of Run) so a cancel can find and kill the
	// process mid-scan. Nuclei exits non-zero even when it finds issues, so the
	// error from Wait is intentionally ignored.
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("nuclei: could not start: %w", err)
	}
	registerDastProc(cmd.Process)
	cmd.Wait() //nolint:errcheck — nuclei exits non-zero even when findings exist
	unregisterDastProc(cmd.Process)

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
