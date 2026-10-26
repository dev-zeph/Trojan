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
	"github.com/dev-zeph/trojan/internal/normalizer"
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
	if err := config.EnsureScanners(); err != nil {
		fmt.Fprintf(os.Stderr, "warning: could not install scanners: %s\n", err)
	}

	fresh, _ := scanners.RunAll(projectPath, []scanners.Scanner{scanner}, nil)
	fresh, _ = normalizer.Reduce(fresh)

	res := &VerifyResult{Fixed: true, Scanner: target.Scanner, RuleID: target.RuleID, FindingID: id}
	want := relPath(projectPath, target.FilePath)
	for _, f := range fresh {
		if f.RuleID == target.RuleID && relPath(projectPath, f.FilePath) == want {
			res.Fixed = false
			res.StillAt = append(res.StillAt, fmt.Sprintf("%s:%d", f.FilePath, f.LineNumber))
		}
	}
	return res, nil
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
		projectPath, err := project(ctx, req)
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		id, err := req.RequireString("id")
		if err != nil {
			return mcp.NewToolResultError("missing required parameter: id"), nil
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
			return mcp.NewToolResultError("verification failed: " + msg), nil
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
				}
			}
			saveLatestScan(projectPath, scan) //nolint:errcheck // the verification itself succeeded
		}
		return mcp.NewToolResultText(fmt.Sprintf("VERIFIED FIXED: %s no longer reports rule %s in that file. Finding %s is marked fixed.", res.Scanner, res.RuleID, id)), nil
	}
}
