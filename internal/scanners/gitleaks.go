package scanners

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/dev-zeph/trojan/internal/normalizer"
)

// Gitleaks implements the Scanner interface for secrets detection.
//
// It always scans the files on disk, so secrets in code that was never
// committed (a new project, a folder with no .git, uncommitted edits) are
// found. When the project is a git repository it also scans the commit
// history, which catches secrets that were committed and later deleted.
type Gitleaks struct{}

func (g Gitleaks) Name() string     { return "gitleaks" }
func (g Gitleaks) Category() string { return "secrets" }

func (g Gitleaks) IsAvailable() bool {
	return IsInstalled("gitleaks")
}

// gitleaksConfig extends the built-in Gitleaks rules and skips folders that
// are not the project's own source. Without it a file scan reads every
// dependency in node_modules and Trojan's own .trojan/ store, which holds
// code snippets from earlier scans and would report each secret again.
const gitleaksConfig = `[extend]
useDefault = true

[allowlist]
description = "Trojan: not project source"
paths = [
  '''(^|/)node_modules/''',
  '''(^|/)\.trojan/''',
  '''(^|/)\.git/''',
  '''(^|/)vendor/''',
  '''(^|/)dist/''',
  '''(^|/)build/''',
  '''(^|/)\.next/''',
  '''(^|/)\.nuxt/''',
  '''(^|/)\.svelte-kit/''',
  '''(^|/)coverage/''',
  '''(^|/)__pycache__/''',
  '''(^|/)\.?venv/''',
  '''(^|/)target/''',
  '''\.min\.js$''',
  '''(^|/)(package-lock\.json|yarn\.lock|pnpm-lock\.yaml|bun\.lockb|composer\.lock|Cargo\.lock|go\.sum|poetry\.lock)$''',
]
`

func (g Gitleaks) Run(projectPath string) ([]normalizer.Finding, error) {
	if !g.IsAvailable() {
		return nil, fmt.Errorf("gitleaks not found: run 'trojan init' to install it")
	}

	cfgDir, err := os.MkdirTemp("", "trojan-gitleaks-")
	if err != nil {
		return nil, fmt.Errorf("gitleaks config: %w", err)
	}
	defer os.RemoveAll(cfgDir)
	cfgPath := filepath.Join(cfgDir, "gitleaks.toml")
	if err := os.WriteFile(cfgPath, []byte(gitleaksConfig), 0o600); err != nil {
		return nil, fmt.Errorf("gitleaks config: %w", err)
	}

	// Files on disk: always.
	results, err := runGitleaks(projectPath, cfgPath, false)
	if err != nil {
		return nil, err
	}
	results = dropLocalOnlyFiles(projectPath, results)
	results = dedupeGitleaksResults(results)

	// Commit history: only for a git repo with a working git. A failure here
	// keeps the file results rather than dropping secrets scanning entirely.
	if exists(filepath.Join(projectPath, ".git")) && gitAvailable() {
		if hist, herr := runGitleaks(projectPath, cfgPath, true); herr == nil {
			results = mergeGitleaksResults(results, hist)
		}
	}

	findings := make([]normalizer.Finding, 0, len(results))
	for i, r := range results {
		msg := "Secret found in the project files"
		if r.Commit != "" {
			msg = fmt.Sprintf("Secret found in git history (commit %s). Deleting the file does not remove it from history: rotate the secret.", shortCommit(r.Commit))
		}
		findings = append(findings, normalizer.Finding{
			ID:          fmt.Sprintf("gitleaks-%d", i),
			Scanner:     g.Name(),
			Category:    g.Category(),
			Severity:    normalizer.SeverityHigh, // secrets are always high severity
			Title:       fmt.Sprintf("Leaked %s", r.Description),
			RawMessage:  msg,
			FilePath:    r.File,
			LineNumber:  r.StartLine,
			CodeSnippet: r.Match,
			RuleID:      r.RuleID,
			Status:      normalizer.StatusOpen,
		})
	}

	return findings, nil
}

// runGitleaks runs one gitleaks pass. history=false scans the files on disk
// (--no-git); history=true scans the commit log.
func runGitleaks(projectPath, cfgPath string, history bool) ([]gitleaksResult, error) {
	// --exit-code 0: finding secrets is not an error, so any non-zero exit is
	// a real failure. Gitleaks exits 1 both for "leaks found" and for fatal
	// errors (a bad flag, a bad config); treating 1 as success once hid a
	// broken run as "no secrets" on every scan. -q is not a gitleaks flag:
	// --log-level error keeps stderr quiet instead. "-" is stdout on every OS.
	args := []string{"detect", "--source", projectPath, "--config", cfgPath,
		"--report-format", "json", "--report-path", "-",
		"--no-banner", "--log-level", "error", "--exit-code", "0"}
	if !history {
		args = append(args, "--no-git")
	}
	cmd := exec.Command(ManagedBinary("gitleaks"), args...)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("gitleaks failed: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	if len(output) == 0 {
		return nil, nil
	}
	var results []gitleaksResult
	if err := json.Unmarshal(output, &results); err != nil {
		return nil, fmt.Errorf("failed to parse gitleaks output: %w", err)
	}
	return results, nil
}

// dropLocalOnlyFiles removes secrets found in files that never leave the
// developer's machine. A gitignored .env.local holding real keys is the
// correct setup, and reporting it on every scan would bury real leaks.
//
// In a git work tree, a file is local-only when git ignores it; a .env that
// is NOT ignored is kept, because it is one `git add .` from being pushed.
// Outside git, .env files are treated as local-only, except example/sample/
// template copies, which exist to be shared.
func dropLocalOnlyFiles(projectPath string, results []gitleaksResult) []gitleaksResult {
	if len(results) == 0 {
		return results
	}
	ignored, ok := gitIgnoredFiles(projectPath, results)
	kept := results[:0]
	for _, r := range results {
		if ok {
			if ignored[r.File] {
				continue
			}
		} else if isLocalEnvFile(r.File) {
			continue
		}
		kept = append(kept, r)
	}
	return kept
}

// gitIgnoredFiles asks git which of the result files it ignores. ok is false
// when git can't answer (no git, or the project is not in a work tree).
func gitIgnoredFiles(projectPath string, results []gitleaksResult) (map[string]bool, bool) {
	if !gitAvailable() {
		return nil, false
	}
	var in strings.Builder
	seen := map[string]bool{}
	for _, r := range results {
		if !seen[r.File] {
			seen[r.File] = true
			in.WriteString(r.File)
			in.WriteByte('\n')
		}
	}
	cmd := exec.Command("git", "-C", projectPath, "check-ignore", "--stdin")
	cmd.Stdin = strings.NewReader(in.String())
	out, err := cmd.Output()
	if err != nil {
		// Exit 1 means "nothing ignored"; anything else means git can't tell.
		if exitErr, isExit := err.(*exec.ExitError); !isExit || exitErr.ExitCode() != 1 {
			return nil, false
		}
	}
	ignored := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if line != "" {
			ignored[line] = true
		}
	}
	return ignored, true
}

func isLocalEnvFile(path string) bool {
	base := strings.ToLower(filepath.Base(path))
	if base != ".env" && !strings.HasPrefix(base, ".env.") {
		return false
	}
	for _, shared := range []string{"example", "sample", "template", "dist"} {
		if strings.HasSuffix(base, "."+shared) {
			return false
		}
	}
	return true
}

// dedupeGitleaksResults keeps one result per file, line and rule. Minified
// files can repeat the same match dozens of times on one line.
func dedupeGitleaksResults(results []gitleaksResult) []gitleaksResult {
	seen := map[string]bool{}
	kept := results[:0]
	for _, r := range results {
		key := fmt.Sprintf("%s\x00%d\x00%s", r.File, r.StartLine, r.RuleID)
		if seen[key] {
			continue
		}
		seen[key] = true
		kept = append(kept, r)
	}
	return kept
}

// mergeGitleaksResults adds history results whose secret was not already
// found in the current files, so a secret still in the code is reported once
// (at its current location) and one that only lives in history still shows.
func mergeGitleaksResults(files, history []gitleaksResult) []gitleaksResult {
	seen := make(map[string]bool, len(files))
	for _, r := range files {
		seen[r.RuleID+"\x00"+r.Secret] = true
	}
	for _, r := range history {
		key := r.RuleID + "\x00" + r.Secret
		if seen[key] {
			continue
		}
		seen[key] = true
		files = append(files, r)
	}
	return files
}

func shortCommit(c string) string {
	if len(c) > 8 {
		return c[:8]
	}
	return c
}

type gitleaksResult struct {
	Description string `json:"Description"`
	StartLine   int    `json:"StartLine"`
	Match       string `json:"Match"`
	Secret      string `json:"Secret"`
	File        string `json:"File"`
	Commit      string `json:"Commit"`
	RuleID      string `json:"RuleID"`
}
