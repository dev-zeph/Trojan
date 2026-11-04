package scanners

import (
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/dev-zeph/trojan/internal/normalizer"
)

// trojanRulesFS holds Trojan's own Semgrep rules, shipped inside the binary.
// Each rule file has a sibling test file (same name, .php) in semgreprules/
// for `semgrep --test`; only the .yaml rules are embedded.
//
//go:embed semgreprules/*.yaml
var trojanRulesFS embed.FS

// trojanRuleIDPrefix marks Trojan's own rules. Semgrep prefixes a local
// rule's check_id with its config file's path (a random temp dir here), so the
// reported ID is normalized back to "trojan.<rule-id>" (see normalizeRuleID).
const trojanRuleIDPrefix = "trojan-"

// phpRulePacks are the Semgrep registry packs added for PHP projects, on top
// of --config=auto. auto alone misses the echoed-request XSS rule and other
// PHP rules in p/php; the packs alone drop some auto-only rules, so both run.
var phpRulePacks = []string{"p/php", "p/owasp-top-ten"}

// Semgrep implements the Scanner interface for static analysis.
//
// PHP is set by RelevantScanners when the project contains PHP. It adds the
// PHP rule packs and Trojan's own PHP rules; every other project runs with
// exactly the same arguments as before.
type Semgrep struct {
	PHP bool
}

func (s Semgrep) Name() string     { return "semgrep" }
func (s Semgrep) Category() string { return "sast" }

func (s Semgrep) IsAvailable() bool {
	return IsInstalled("semgrep")
}

// semgrepArgs builds the semgrep command line. extraConfigs are added as
// further --config flags right after --config=auto (Semgrep runs the union of
// every --config it is given).
func semgrepArgs(projectPath string, extraConfigs []string) []string {
	args := []string{"--config=auto"}
	for _, c := range extraConfigs {
		args = append(args, "--config", c)
	}
	// Parallel jobs + skip generated/vendor dirs + cap large files.
	args = append(args,
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
	)
	return args
}

// writeTrojanRules copies the embedded rules into a fresh temp directory for
// semgrep to read. The caller removes the directory when the run is done.
func writeTrojanRules() (string, error) {
	dir, err := os.MkdirTemp("", "trojan-semgrep-rules-")
	if err != nil {
		return "", err
	}
	entries, err := fs.ReadDir(trojanRulesFS, "semgreprules")
	if err != nil {
		os.RemoveAll(dir)
		return "", err
	}
	for _, e := range entries {
		data, err := trojanRulesFS.ReadFile("semgreprules/" + e.Name())
		if err != nil {
			os.RemoveAll(dir)
			return "", err
		}
		if err := os.WriteFile(filepath.Join(dir, e.Name()), data, 0o600); err != nil {
			os.RemoveAll(dir)
			return "", err
		}
	}
	return dir, nil
}

func (s Semgrep) Run(projectPath string) ([]normalizer.Finding, error) {
	if !s.IsAvailable() {
		return nil, fmt.Errorf("semgrep not found: run 'trojan init' to install it")
	}

	var extra []string
	if s.PHP {
		extra = append(extra, phpRulePacks...)
		// Trojan's own rules are best effort: if they can't be written, the
		// scan still runs with the registry rules.
		if dir, err := writeTrojanRules(); err == nil {
			defer os.RemoveAll(dir)
			extra = append(extra, dir)
		}
	}
	args := semgrepArgs(projectPath, extra)

	bin := ManagedBinary("semgrep")
	output, err := exec.Command(bin, args...).Output()
	if _, isExit := err.(*exec.ExitError); err != nil && !isExit {
		// The managed binary could not start at all (e.g. ~/.trojan/bin/semgrep
		// is a venv script whose python3 was removed: "fork/exec ...: no such
		// file or directory"). Fall back to a semgrep on PATH rather than
		// silently dropping SAST from the scan.
		if sys, lerr := exec.LookPath("semgrep"); lerr == nil && sys != bin {
			output, err = exec.Command(sys, args...).Output()
		}
	}
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
		ruleID := normalizeRuleID(r.CheckID)
		title := r.Extra.Metadata.TrojanTitle
		if title == "" {
			title = semgrepTitle(ruleID)
		}
		findings = append(findings, normalizer.Finding{
			ID:          fmt.Sprintf("semgrep-%d", i),
			Scanner:     s.Name(),
			Category:    s.Category(),
			Severity:    normalizeSemgrepSeverity(r.Extra.Severity),
			Title:       title,
			RawMessage:  r.Extra.Message,
			FilePath:    r.Path,
			LineNumber:  r.Start.Line,
			CodeSnippet: strings.TrimSpace(r.Extra.Lines),
			RuleID:      ruleID,
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
			CWE   stringOrList `json:"cwe"`
			OWASP stringOrList `json:"owasp"`
			// TrojanTitle is the plain-English title on Trojan's own rules.
			TrojanTitle string `json:"trojan-title"`
		} `json:"metadata"`
	} `json:"extra"`
}

// stringOrList accepts a Semgrep metadata field as either a JSON list or a
// single JSON string — both forms appear across registry rules, for cwe and
// owasp alike (e.g. the "debug-enabled" rule emits owasp as a bare string).
// Without this, one scalar value fails json.Unmarshal of the whole document
// and the entire Semgrep pass is silently dropped.
type stringOrList []string

func (c *stringOrList) UnmarshalJSON(b []byte) error {
	var list []string
	if err := json.Unmarshal(b, &list); err == nil {
		*c = list
		return nil
	}
	var one string
	if err := json.Unmarshal(b, &one); err == nil {
		*c = []string{one}
		return nil
	}
	*c = nil
	return nil
}

// normalizeRuleID turns a Trojan rule's path-prefixed check_id
// ("var.folders.x.trojan-semgrep-rules-123.trojan-php-xxe-request-xml") into
// a stable "trojan.trojan-php-xxe-request-xml". Registry rule IDs are
// returned unchanged.
func normalizeRuleID(checkID string) string {
	last := checkID
	if i := strings.LastIndex(checkID, "."); i >= 0 {
		last = checkID[i+1:]
	}
	if strings.HasPrefix(last, trojanRuleIDPrefix) && strings.Contains(checkID, "trojan-semgrep-rules-") {
		return "trojan." + last
	}
	return checkID
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

// semgrepTitle is the finding title for a Semgrep rule: a plain-English title
// for common rules, else one derived from the rule ID.
func semgrepTitle(ruleID string) string {
	parts := strings.Split(ruleID, ".")
	if t, ok := friendlySemgrepTitles[parts[len(parts)-1]]; ok {
		return t
	}
	return ruleIDToTitle(ruleID)
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
