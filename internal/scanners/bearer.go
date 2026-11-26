package scanners

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/dev-zeph/trojan/internal/normalizer"
	"gopkg.in/yaml.v3"
)

// CustomRulePrefix marks a rule id that the scanned project defines itself
// (for example a rule in its own bearer.yml external-rule-dir). Such ids can
// name the project's internals, so the server never puts them in the shared
// explanation cache; it treats them as personal.
const CustomRulePrefix = "custom:"

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
	// Bearer reads bearer.yml from its working directory. Run it in the project,
	// so the config it uses is always the one customRuleIDs reads below.
	cmd.Dir = projectPath
	custom := bearerCustomRuleIDs(projectPath)
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
				RuleID:      markCustomRule(f.ID, custom),
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

// markCustomRule prefixes a rule id the project defines itself with "custom:".
func markCustomRule(id string, custom map[string]bool) string {
	if custom[id] && !strings.HasPrefix(id, CustomRulePrefix) {
		return CustomRulePrefix + id
	}
	return id
}

// bearerCustomRuleIDs returns the ids of rules the project defines in its own
// bearer.yml (scan.external-rule-dir). Their findings still show to the user;
// only the id is marked custom so it stays out of shared caches. Unreadable or
// missing config means no custom rules.
func bearerCustomRuleIDs(projectPath string) map[string]bool {
	ids := map[string]bool{}
	cfgPath := filepath.Join(projectPath, "bearer.yml")
	data, err := os.ReadFile(cfgPath)
	if err != nil {
		return ids
	}
	var cfg struct {
		Scan struct {
			ExternalRuleDir yaml.Node `yaml:"external-rule-dir"`
		} `yaml:"scan"`
	}
	if yaml.Unmarshal(data, &cfg) != nil {
		return ids
	}
	var dirs []string
	switch cfg.Scan.ExternalRuleDir.Kind {
	case yaml.ScalarNode:
		dirs = []string{cfg.Scan.ExternalRuleDir.Value}
	case yaml.SequenceNode:
		_ = cfg.Scan.ExternalRuleDir.Decode(&dirs)
	}
	for _, d := range dirs {
		if strings.TrimSpace(d) == "" {
			continue
		}
		if !filepath.IsAbs(d) {
			d = filepath.Join(projectPath, d)
		}
		_ = filepath.WalkDir(d, func(path string, e os.DirEntry, err error) error {
			if err != nil || e.IsDir() {
				return nil
			}
			ext := strings.ToLower(filepath.Ext(path))
			if ext != ".yml" && ext != ".yaml" {
				return nil
			}
			body, rerr := os.ReadFile(path)
			if rerr != nil {
				return nil
			}
			var rule struct {
				Metadata struct {
					ID string `yaml:"id"`
				} `yaml:"metadata"`
			}
			if yaml.Unmarshal(body, &rule) == nil && rule.Metadata.ID != "" {
				ids[rule.Metadata.ID] = true
			}
			return nil
		})
	}
	return ids
}
