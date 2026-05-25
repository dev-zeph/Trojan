package mcpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"

	"github.com/dev-zeph/trojan/internal/config"
	"github.com/dev-zeph/trojan/internal/normalizer"
)

// Serve starts the Trojan MCP server over stdio for the given project path.
// The AI editor (Claude Code, Cursor, etc.) spawns this process and communicates
// via stdin/stdout using the Model Context Protocol JSON-RPC format.
func Serve(projectPath string) error {
	// Require a logged-in Pro user — MCP is a Pro feature.
	cfg, err := config.LoadConfig()
	if err != nil || cfg.AccessToken == "" {
		return fmt.Errorf("not logged in — run `trojan login` first")
	}
	if !config.IsProFromToken(cfg.AccessToken) {
		return fmt.Errorf("MCP integration requires a Pro subscription — visit https://trojan.dev/pricing to upgrade")
	}

	s := server.NewMCPServer(
		"trojan",
		"0.0.1",
		server.WithDescription("Trojan security scanner — read and act on vulnerability findings in your codebase."),
	)

	s.AddTool(
		mcp.NewTool("get_findings",
			mcp.WithDescription("Return all vulnerability findings from the latest Trojan scan, including severity, file path, line number, and status."),
		),
		handleGetFindings(projectPath),
	)

	s.AddTool(
		mcp.NewTool("get_finding_detail",
			mcp.WithDescription("Return full detail for a specific finding by ID, including the code snippet, raw message, and any AI-generated explanation."),
			mcp.WithString("id",
				mcp.Required(),
				mcp.Description("The finding ID to look up."),
			),
		),
		handleGetFindingDetail(projectPath),
	)

	s.AddTool(
		mcp.NewTool("resolve_finding",
			mcp.WithDescription("Mark a finding as resolved. Use this after applying a fix."),
			mcp.WithString("id",
				mcp.Required(),
				mcp.Description("The finding ID to mark as resolved."),
			),
		),
		handleUpdateStatus(projectPath, normalizer.StatusResolved),
	)

	s.AddTool(
		mcp.NewTool("suppress_finding",
			mcp.WithDescription("Suppress a finding — it will be hidden in future scans. Use for accepted risks or false positives."),
			mcp.WithString("id",
				mcp.Required(),
				mcp.Description("The finding ID to suppress."),
			),
		),
		handleUpdateStatus(projectPath, normalizer.StatusSuppressed),
	)

	s.AddTool(
		mcp.NewTool("run_scan",
			mcp.WithDescription("Trigger a fresh Trojan security scan on the project. Returns the number of findings after the scan completes."),
		),
		handleRunScan(projectPath),
	)

	return server.ServeStdio(s)
}

// --- handlers ---

func handleGetFindings(projectPath string) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		scan, err := loadLatestScan(projectPath)
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}

		out, err := json.MarshalIndent(scan.Findings, "", "  ")
		if err != nil {
			return mcp.NewToolResultError("failed to serialize findings"), nil
		}
		return mcp.NewToolResultText(string(out)), nil
	}
}

func handleGetFindingDetail(projectPath string) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		id, err := req.RequireString("id")
		if err != nil {
			return mcp.NewToolResultError("missing required parameter: id"), nil
		}

		scan, err := loadLatestScan(projectPath)
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}

		for _, f := range scan.Findings {
			if f.ID == id {
				return mcp.NewToolResultText(formatFinding(f)), nil
			}
		}
		return mcp.NewToolResultError(fmt.Sprintf("finding %q not found", id)), nil
	}
}

// formatFinding renders a finding as structured plain text so the AI agent
// can clearly read the explanation and act on the fix steps.
func formatFinding(f normalizer.Finding) string {
	var b strings.Builder

	fmt.Fprintf(&b, "FINDING: %s\n", f.ID)
	fmt.Fprintf(&b, "Title:    %s\n", f.Title)
	fmt.Fprintf(&b, "Severity: %s\n", f.Severity)
	fmt.Fprintf(&b, "Scanner:  %s\n", f.Scanner)
	fmt.Fprintf(&b, "Category: %s\n", f.Category)
	fmt.Fprintf(&b, "Status:   %s\n", f.Status)
	fmt.Fprintf(&b, "Rule:     %s\n\n", f.RuleID)

	fmt.Fprintf(&b, "Location: %s", f.FilePath)
	if f.LineNumber > 0 {
		fmt.Fprintf(&b, ":%d", f.LineNumber)
	}
	fmt.Fprintf(&b, "\n\n")

	if f.CodeSnippet != "" {
		fmt.Fprintf(&b, "Code:\n%s\n\n", f.CodeSnippet)
	}

	fmt.Fprintf(&b, "What this means:\n%s\n\n", f.RawMessage)

	if f.Simply != "" {
		fmt.Fprintf(&b, "Plain-English explanation:\n%s\n\n", f.Simply)
	}

	if len(f.Actions) > 0 {
		fmt.Fprintf(&b, "Recommended actions (apply these to fix the vulnerability):\n")
		for i, action := range f.Actions {
			fmt.Fprintf(&b, "  %d. %s\n", i+1, action)
		}
		fmt.Fprintf(&b, "\n")
	} else {
		fmt.Fprintf(&b, "Recommended actions:\n")
		fmt.Fprintf(&b, "  No AI-generated fix steps available. Review the scanner documentation for rule %s.\n\n", f.RuleID)
	}

	fmt.Fprintf(&b, "To mark this fixed, call: resolve_finding(id: %q)\n", f.ID)
	fmt.Fprintf(&b, "To suppress this rule, call: suppress_finding(id: %q)\n", f.ID)

	return b.String()
}

func handleUpdateStatus(projectPath string, status normalizer.Status) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		id, err := req.RequireString("id")
		if err != nil {
			return mcp.NewToolResultError("missing required parameter: id"), nil
		}

		scan, err := loadLatestScan(projectPath)
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}

		found := false
		for i, f := range scan.Findings {
			if f.ID == id {
				scan.Findings[i].Status = status
				found = true
				break
			}
		}
		if !found {
			return mcp.NewToolResultError(fmt.Sprintf("finding %q not found", id)), nil
		}

		if err := saveLatestScan(projectPath, scan); err != nil {
			return mcp.NewToolResultError("failed to save updated scan: " + err.Error()), nil
		}

		return mcp.NewToolResultText(fmt.Sprintf("finding %s marked as %s", id, status)), nil
	}
}

func handleRunScan(projectPath string) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		cmd := exec.CommandContext(ctx, "trojan", "scan", projectPath)
		cmd.Dir = projectPath
		if err := cmd.Run(); err != nil {
			return mcp.NewToolResultError("scan failed: " + err.Error()), nil
		}

		scan, err := loadLatestScan(projectPath)
		if err != nil {
			return mcp.NewToolResultText("scan completed"), nil
		}

		return mcp.NewToolResultText(fmt.Sprintf(
			"scan completed — %d findings (%d open)",
			len(scan.Findings),
			countOpen(scan.Findings),
		)), nil
	}
}

// --- disk helpers ---

func loadLatestScan(projectPath string) (*normalizer.ScanResult, error) {
	scansDir := filepath.Join(projectPath, ".trojan", "scans")
	entries, err := os.ReadDir(scansDir)
	if err != nil {
		return nil, fmt.Errorf("no scan results found in %s — run `trojan scan` first", projectPath)
	}

	var files []string
	for _, e := range entries {
		if !e.IsDir() && filepath.Ext(e.Name()) == ".json" {
			files = append(files, e.Name())
		}
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("no scan results found — run `trojan scan` first")
	}
	sort.Strings(files)

	data, err := os.ReadFile(filepath.Join(scansDir, files[len(files)-1]))
	if err != nil {
		return nil, fmt.Errorf("could not read scan file: %w", err)
	}

	var result normalizer.ScanResult
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("could not parse scan file: %w", err)
	}
	return &result, nil
}

func saveLatestScan(projectPath string, result *normalizer.ScanResult) error {
	scansDir := filepath.Join(projectPath, ".trojan", "scans")
	entries, err := os.ReadDir(scansDir)
	if err != nil {
		return err
	}

	var files []string
	for _, e := range entries {
		if !e.IsDir() && filepath.Ext(e.Name()) == ".json" {
			files = append(files, e.Name())
		}
	}
	if len(files) == 0 {
		return fmt.Errorf("no scan file to update")
	}
	sort.Strings(files)

	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(scansDir, files[len(files)-1]), data, 0644)
}

func countOpen(findings []normalizer.Finding) int {
	n := 0
	for _, f := range findings {
		if f.Status == normalizer.StatusOpen {
			n++
		}
	}
	return n
}
