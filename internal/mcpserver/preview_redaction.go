package mcpserver

import (
	"context"
	"fmt"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"

	"github.com/dev-zeph/trojan/internal/normalizer"
	"github.com/dev-zeph/trojan/internal/redact"
)

// handlePreviewRedaction powers the preview_redaction MCP tool. It makes the
// redaction layer exercisable: given either a finding id (from the latest
// scan) or raw text, it shows the three views side by side —
//   - local:  the full value, exactly as it is stored on this machine;
//   - ai:     the <SECRET: …> descriptor that is actually sent to Anthropic/Voyage;
//   - upload: the prefix…last4 mask that goes into an uploaded report —
//
// plus the local classification of each detected secret (type, length, prefix,
// entropy, class, checks). It is read-only and never leaves the machine.
func handlePreviewRedaction(project projectFunc) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		view := req.GetString("view", "both") // ai | upload | both | local
		text := req.GetString("text", "")
		id := req.GetString("id", "")

		type secretView struct {
			Type    string   `json:"type"`
			Length  int      `json:"length"`
			Prefix  string   `json:"prefix"`
			Entropy float64  `json:"entropy"`
			Class   string   `json:"class"`
			Checks  []string `json:"checks,omitempty"`
		}
		classifyText := func(path, s string) []secretView {
			out := []secretView{}
			for _, sec := range redact.Find(s) {
				a := redact.Classify(sec.Value, sec.Type, path)
				out = append(out, secretView{
					Type:    sec.Type,
					Length:  len(sec.Value),
					Prefix:  redact.SafePrefixFor(sec),
					Entropy: round2(redact.Entropy(sec.Value)),
					Class:   string(a.Class),
					Checks:  a.Checks,
				})
			}
			return out
		}

		switch {
		case text != "":
			fd := &redact.Finder{}
			resp := map[string]any{
				"input":    "text",
				"detected": classifyText("", text),
			}
			if view == "local" || view == "both" {
				resp["local"] = text
			}
			if view == "ai" || view == "both" {
				resp["ai"] = fd.Redact(text)
			}
			if view == "upload" || view == "both" {
				resp["upload"] = fd.Mask(text)
			}
			return jsonResult(resp)

		case id != "":
			projectPath, err := project(ctx, req)
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			scan, err := loadLatestScan(projectPath)
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			var found *normalizer.Finding
			for i := range scan.Findings {
				if scan.Findings[i].ID == id {
					found = &scan.Findings[i]
					break
				}
			}
			if found == nil {
				return mcp.NewToolResultError(fmt.Sprintf("finding %q not found in the latest scan of %s", id, projectPath)), nil
			}
			resp := map[string]any{
				"input":    "finding",
				"id":       id,
				"detected": classifyText(found.FilePath, found.CodeSnippet+"\n"+found.SurroundingCode+"\n"+found.RawMessage),
			}
			if view == "local" || view == "both" {
				resp["local"] = compactFinding(*found)
			}
			if view == "ai" || view == "both" {
				resp["ai"] = compactFinding(redact.ForAI(*found))
			}
			if view == "upload" || view == "both" {
				resp["upload"] = compactFinding(redact.ForUpload(*found))
			}
			return jsonResult(resp)

		default:
			return mcp.NewToolResultError(`preview_redaction needs either "id" (a finding from the latest scan) or "text" (a string to run through redaction)`), nil
		}
	}
}

// compactFinding is the subset of a finding whose fields can carry a secret,
// shown so the three views can be compared field by field.
func compactFinding(f normalizer.Finding) map[string]any {
	return map[string]any{
		"title":            f.Title,
		"location":         f.FilePath,
		"rule":             f.RuleID,
		"code_snippet":     f.CodeSnippet,
		"surrounding_code": f.SurroundingCode,
		"raw_message":      f.RawMessage,
	}
}

func round2(f float64) float64 {
	return float64(int(f*100+0.5)) / 100
}
