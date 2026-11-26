package mcpserver

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"

	"github.com/dev-zeph/trojan/internal/config"
	"github.com/dev-zeph/trojan/internal/memory"
	"github.com/dev-zeph/trojan/internal/normalizer"
	"github.com/dev-zeph/trojan/internal/redact"
	"github.com/dev-zeph/trojan/internal/scanners"
)

// ── verify_fix ───────────────────────────────────────────────────────────────
//
// Re-runs only the scanner that reported a finding and checks whether the same
// rule still fires in the same file. Line numbers aren't compared: a fix
// usually moves them. Runs in its own process (`trojan mcp verify-once`) so
// scanner output can't interfere with the MCP connection.

// VerifyResult is what verify-once prints after the VerifyMarker prefix.
type VerifyResult struct {
	Fixed     bool     `json:"fixed"`
	StillAt   []string `json:"still_at,omitempty"`
	Scanner   string   `json:"scanner"`
	RuleID    string   `json:"rule_id"`
	FindingID string   `json:"finding_id"`
	// NotFound is set when the finding's file cannot be resolved against the
	// scan root. A missing file must never be reported as fixed.
	NotFound bool   `json:"not_found,omitempty"`
	File     string `json:"file,omitempty"`
}

const VerifyMarker = "TROJAN_VERIFY "

// VerifyOnce re-checks one finding in a project.
func VerifyOnce(projectPath, id string) (*VerifyResult, error) {
	scan, err := loadLatestScan(projectPath)
	if err != nil {
		return nil, err
	}
	var target *normalizer.Finding
	for i := range scan.Findings {
		if scan.Findings[i].ID == id {
			target = &scan.Findings[i]
			break
		}
	}
	if target == nil {
		return nil, fmt.Errorf("finding %q isn't in this project's latest code scan. For a website finding, run start_website_test again to confirm the fix", id)
	}

	var scanner scanners.Scanner
	for _, s := range scanners.DefaultScanners() {
		if s.Name() == target.Scanner {
			scanner = s
		}
	}
	if scanner == nil {
		return nil, fmt.Errorf("can't re-run scanner %q on its own; use run_scan instead", target.Scanner)
	}

	absFile, ok := normalizer.ResolveAgainstRoot(projectPath, target.FilePath)
	if !ok {
		return &VerifyResult{Fixed: false, NotFound: true, Scanner: target.Scanner, RuleID: target.RuleID, FindingID: id, File: target.FilePath}, nil
	}
	target.FilePath = normalizer.RelToProject(projectPath, target.FilePath)
	_ = absFile

	if err := config.EnsureScanners(); err != nil {
		fmt.Fprintf(os.Stderr, "warning: could not install scanners: %s\n", err)
	}

	fresh, results := scanners.RunAll(projectPath, []scanners.Scanner{scanner}, nil)
	// A scanner that failed to run (e.g. Semgrep couldn't download its rules)
	// returns no findings, which must not read as "the finding is gone".
	for _, r := range results {
		if r.Err != nil {
			return nil, fmt.Errorf("couldn't confirm the fix right now. Try verify_fix again in a moment")
		}
	}
	// Do not Reduce: path filters and cross-finding dedupe can drop the
	// finding's own file when the same value also appears elsewhere.

	res := &VerifyResult{Fixed: true, Scanner: target.Scanner, RuleID: target.RuleID, FindingID: id, File: target.FilePath}
	if findingStillPresent(*target, projectPath, absFile, fresh) {
		res.Fixed = false
		res.StillAt = stillAtLocations(*target, projectPath, absFile, fresh)
	}
	return res, nil
}

const verifyLineSlack = 5

func findingStillPresent(target normalizer.Finding, projectPath, absFile string, fresh []normalizer.Finding) bool {
	want := normalizer.RelToProject(projectPath, target.FilePath)
	for _, f := range fresh {
		if !sameVerifyRule(f.RuleID, target.RuleID) {
			continue
		}
		got := normalizer.RelToProject(projectPath, f.FilePath)
		if got != want && !sameVerifyFile(absFile, f.FilePath, projectPath) {
			continue
		}
		if target.LineNumber <= 0 || f.LineNumber <= 0 || absInt(f.LineNumber-target.LineNumber) <= verifyLineSlack {
			return true
		}
	}
	if val := secretValueForVerify(target); val != "" && absFile != "" {
		if body, err := os.ReadFile(absFile); err == nil && bytes.Contains(body, []byte(val)) {
			return true
		}
	}
	return false
}

func stillAtLocations(target normalizer.Finding, projectPath, absFile string, fresh []normalizer.Finding) []string {
	var out []string
	want := normalizer.RelToProject(projectPath, target.FilePath)
	for _, f := range fresh {
		if !sameVerifyRule(f.RuleID, target.RuleID) {
			continue
		}
		got := normalizer.RelToProject(projectPath, f.FilePath)
		if got != want && !sameVerifyFile(absFile, f.FilePath, projectPath) {
			continue
		}
		out = append(out, fmt.Sprintf("%s:%d", f.FilePath, f.LineNumber))
	}
	if len(out) == 0 {
		out = append(out, want)
	}
	return out
}

func sameVerifyRule(a, b string) bool {
	return strings.EqualFold(strings.TrimSpace(a), strings.TrimSpace(b))
}

func sameVerifyFile(absFile, stored, projectPath string) bool {
	if absFile == "" || stored == "" {
		return false
	}
	other, ok := normalizer.ResolveAgainstRoot(projectPath, stored)
	if !ok {
		return false
	}
	return filepath.Clean(absFile) == filepath.Clean(other)
}

func secretValueForVerify(f normalizer.Finding) string {
	blob := strings.TrimSpace(f.CodeSnippet + "\n" + f.SurroundingCode)
	if hits := redact.Find(blob); len(hits) > 0 {
		best := hits[0]
		for _, h := range hits[1:] {
			if len(h.Value) > len(best.Value) {
				best = h
			}
		}
		if len(best.Value) >= 4 {
			return best.Value
		}
	}
	// gitleaks Match is often the raw value, possibly wrapped in quotes.
	v := strings.TrimSpace(f.CodeSnippet)
	v = strings.Trim(v, `"'`)
	if len(v) >= 8 && !strings.ContainsAny(v, " \n\t") {
		return v
	}
	return ""
}

func absInt(n int) int {
	if n < 0 {
		return -n
	}
	return n
}

func relPath(root, p string) string {
	if filepath.IsAbs(p) {
		if r, err := filepath.Rel(root, p); err == nil {
			return filepath.ToSlash(r)
		}
	}
	return filepath.ToSlash(filepath.Clean(p))
}

func handleVerifyFix(project projectFunc) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		id, err := req.RequireString("id")
		if err != nil {
			return mcp.NewToolResultError("missing required parameter: id"), nil
		}

		// A website / pen-test finding is verified by replaying its recorded
		// proof against the live endpoint (seconds), not by re-running the code
		// scanner. Route those IDs to the targeted retest.
		if siteDir, _, ok := findWebsiteFinding(id); ok {
			return verifyFixWebsite(ctx, siteDir, id), nil
		}

		projectPath, err := project(ctx, req)
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}

		// Findings promoted from Trojan intel are re-checked in-process against
		// the lockfiles (no scanner to re-run).
		if strings.HasPrefix(id, "intel-") {
			if text, ok := verifyIntelFinding(projectPath, id); ok {
				return mcp.NewToolResultText(text), nil
			}
		}

		exe, err := os.Executable()
		if err != nil {
			return mcp.NewToolResultError("could not locate the Trojan binary: " + err.Error()), nil
		}
		cmd := exec.CommandContext(ctx, exe, "mcp", "verify-once", projectPath, id)
		cmd.Dir = projectPath
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		out, runErr := cmd.Output()

		var res *VerifyResult
		sc := bufio.NewScanner(bytes.NewReader(out))
		for sc.Scan() {
			if line := sc.Text(); strings.HasPrefix(line, VerifyMarker) {
				res = &VerifyResult{}
				if json.Unmarshal([]byte(strings.TrimPrefix(line, VerifyMarker)), res) != nil {
					res = nil
				}
			}
		}
		if res == nil {
			msg := strings.TrimSpace(stderr.String())
			if msg == "" && runErr != nil {
				msg = runErr.Error()
			}
			if strings.HasPrefix(msg, "couldn't confirm") {
				return mcp.NewToolResultText(msg), nil // not a verdict: nothing is marked
			}
			return mcp.NewToolResultError("verification failed: " + msg), nil
		}

		if res.NotFound {
			return mcp.NewToolResultText(fmt.Sprintf("NOT FOUND: could not find %s for finding %s in the scan folder. The file is resolved against the project, not the current directory. The finding is not marked fixed.",
				res.File, res.FindingID)), nil
		}
		if !res.Fixed {
			return mcp.NewToolResultText(fmt.Sprintf("NOT FIXED: %s (rule %s) still reports this at %s. Look at those lines and try again.",
				res.Scanner, res.RuleID, strings.Join(res.StillAt, ", "))), nil
		}

		// Confirmed gone: record it so the dashboard and get_findings agree.
		if scan, err := loadLatestScan(projectPath); err == nil {
			for i := range scan.Findings {
				if scan.Findings[i].ID == id {
					scan.Findings[i].Status = normalizer.StatusResolved
					recordMemory(projectPath, scan.Findings[i], memory.KindFixed,
						fmt.Sprintf("verify_fix: %s no longer reports rule %s in this file", res.Scanner, res.RuleID))
				}
			}
			saveLatestScan(projectPath, scan) //nolint:errcheck // the verification itself succeeded
		}
		return mcp.NewToolResultText(fmt.Sprintf("VERIFIED FIXED: %s no longer reports rule %s in that file. Finding %s is marked fixed.", res.Scanner, res.RuleID, id)), nil
	}
}
