package mcpserver

import (
	"context"
	"fmt"
	"os"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"

	"github.com/dev-zeph/trojan/internal/ai"
	"github.com/dev-zeph/trojan/internal/memory"
	"github.com/dev-zeph/trojan/internal/normalizer"
)

// ScanTriage runs the AI false-alarm check on a fresh code scan's findings,
// writing verdicts onto them, and returns a note when it couldn't finish. It
// is set by cmd/trojan (the composition root, which owns sign-in and the code
// index); nil means run_scan saves findings without the check.
var ScanTriage func(projectPath string, findings []normalizer.Finding) (note string)

// handleMarkReal records that the user says a code finding is real: the
// verdict in the latest scan becomes "confirmed", and project memory keeps the
// decision so later scans never hide it again.
func handleMarkReal(project projectFunc) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		id, err := req.RequireString("id")
		if err != nil {
			return mcp.NewToolResultError("missing required parameter: id"), nil
		}
		projectPath, err := project(ctx, req)
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		scan, err := loadLatestScan(projectPath)
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		for i, f := range scan.Findings {
			if f.ID != id {
				continue
			}
			store, err := memory.Open(projectPath)
			if err != nil {
				return mcp.NewToolResultError("could not open project memory: " + err.Error()), nil
			}
			err = store.MarkReal(f, memory.SourceClaude, "marked as a real issue through the MCP server")
			store.Close()
			if err != nil {
				return mcp.NewToolResultError("could not save the decision: " + err.Error()), nil
			}
			scan.Findings[i].Verdict = "confirmed"
			scan.Findings[i].VerdictReason = ai.MarkedRealRationale
			scan.Findings[i].VerdictConfidence = 1
			if err := saveLatestScan(projectPath, scan); err != nil {
				fmt.Fprintf(os.Stderr, "trojan: could not update scan file: %s\n", err)
			}
			return mcp.NewToolResultText(fmt.Sprintf("finding %s marked as a real issue; Trojan will keep showing it", id)), nil
		}
		return mcp.NewToolResultError(fmt.Sprintf("finding %q not found", id)), nil
	}
}
