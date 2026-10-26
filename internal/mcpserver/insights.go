package mcpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"

	"github.com/dev-zeph/trojan/internal/normalizer"
	"github.com/dev-zeph/trojan/internal/orgcontext"
)

// ── Overviews: summary, privacy, dependencies ────────────────────────────────

func jsonResult(v any) (*mcp.CallToolResult, error) {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return mcp.NewToolResultError("failed to serialize result"), nil
	}
	return mcp.NewToolResultText(string(data)), nil
}

// withScan resolves the project and loads its latest scan before calling fn.
func withScan(project projectFunc, fn func(projectPath string, scan *normalizer.ScanResult) (*mcp.CallToolResult, error)) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		projectPath, err := project(ctx, req)
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		scan, err := loadLatestScan(projectPath)
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		return fn(projectPath, scan)
	}
}

func handleSecuritySummary(project projectFunc) server.ToolHandlerFunc {
	return withScan(project, func(projectPath string, scan *normalizer.ScanResult) (*mcp.CallToolResult, error) {
		bySeverity := map[string]int{}
		var open []normalizer.Finding
		for _, f := range scan.Findings {
			if f.Status == normalizer.StatusOpen {
				bySeverity[string(f.Severity)]++
				open = append(open, f)
			}
		}
		sort.SliceStable(open, func(i, j int) bool { return severityRank[open[i].Severity] > severityRank[open[j].Severity] })

		type urgent struct {
			ID, Severity, Title, Location, Explanation string
		}
		var top []urgent
		for _, f := range open {
			if len(top) == 5 || severityRank[f.Severity] < severityRank[normalizer.SeverityHigh] {
				break
			}
			top = append(top, urgent{f.ID, string(f.Severity), f.Title, fmt.Sprintf("%s:%d", f.FilePath, f.LineNumber), f.Simply})
		}

		var personalData []string
		if scan.Privacy != nil {
			for _, d := range scan.Privacy.DataTypes {
				personalData = append(personalData, d.Name)
			}
		}
		vulnerable := 0
		for _, p := range scan.Packages {
			if p.CVECount > 0 {
				vulnerable++
			}
		}

		return jsonResult(map[string]any{
			"project":               projectPath,
			"scanned_at":            scan.Timestamp,
			"open_by_severity":      bySeverity,
			"most_urgent":           top,
			"personal_data_handled": personalData,
			"vulnerable_packages":   vulnerable,
			"project_context":       contextStatus(projectPath),
		})
	})
}

func handlePrivacyReport(project projectFunc) server.ToolHandlerFunc {
	return withScan(project, func(projectPath string, scan *normalizer.ScanResult) (*mcp.CallToolResult, error) {
		if scan.Privacy == nil || (len(scan.Privacy.DataTypes) == 0 && len(scan.Privacy.ThirdParty) == 0) {
			return mcp.NewToolResultText("The latest scan found no personal data handling or third-party data flows. Run run_scan if the code has changed."), nil
		}
		return jsonResult(scan.Privacy)
	})
}

func handleDependencyRisks(project projectFunc) server.ToolHandlerFunc {
	return withScan(project, func(projectPath string, scan *normalizer.ScanResult) (*mcp.CallToolResult, error) {
		type risk struct {
			Package    string   `json:"package"`
			Version    string   `json:"version"`
			Ecosystem  string   `json:"ecosystem"`
			Direct     bool     `json:"direct"`
			Severity   string   `json:"severity"`
			FixVersion string   `json:"fix_version,omitempty"`
			Advisories []string `json:"advisories,omitempty"`
		}
		var risks []risk
		for _, p := range scan.Packages {
			if p.CVECount == 0 {
				continue
			}
			var ids []string
			for _, a := range p.Advisories {
				ids = append(ids, a.ID)
			}
			risks = append(risks, risk{p.Name, p.Version, p.Ecosystem, p.Direct, string(p.HighestSeverity), p.FixVersion, ids})
		}
		if len(risks) == 0 {
			return mcp.NewToolResultText("No packages with known vulnerabilities in the latest scan."), nil
		}
		sort.SliceStable(risks, func(i, j int) bool {
			return severityRank[normalizer.Severity(risks[i].Severity)] > severityRank[normalizer.Severity(risks[j].Severity)]
		})
		return jsonResult(risks)
	})
}

// ── Project context ──────────────────────────────────────────────────────────

// contextStatus tells the AI tool whether the project context exists and how
// old it is, so it can offer to create or refresh it.
func contextStatus(projectPath string) map[string]any {
	path := orgcontext.Path(projectPath)
	info, err := os.Stat(path)
	if err != nil {
		return map[string]any{"exists": false, "hint": "No project context yet. Offer to fill it in with update_project_context."}
	}
	return map[string]any{"exists": true, "updated_at": info.ModTime().UTC().Format(time.RFC3339)}
}

func handleGetProjectContext(project projectFunc) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		projectPath, err := project(ctx, req)
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		path := orgcontext.Path(projectPath)
		if !orgcontext.Exists(path) {
			return mcp.NewToolResultText("This project has no Trojan context yet. Read the codebase, draft one (what the app does, sensitive data, trust boundaries, threat actors), show it to the user, and save it with update_project_context."), nil
		}
		oc, err := orgcontext.Load(path)
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		return jsonResult(map[string]any{"context": oc, "status": contextStatus(projectPath)})
	}
}

func handleUpdateProjectContext(project projectFunc) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		projectPath, err := project(ctx, req)
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		raw, ok := req.GetArguments()["context"]
		if !ok {
			return mcp.NewToolResultError("missing required parameter: context"), nil
		}
		// Round-trip through JSON so the schema (and its field names) is enforced.
		data, _ := json.Marshal(raw)
		var oc orgcontext.OrgContext
		if s, isString := raw.(string); isString {
			data = []byte(s) // some clients send the object as a JSON string
		}
		if err := json.Unmarshal(data, &oc); err != nil {
			return mcp.NewToolResultError("context doesn't match the expected shape: " + err.Error()), nil
		}
		if oc.App.Name == "" && oc.App.Description == "" {
			return mcp.NewToolResultError("context.app needs at least a name or description"), nil
		}
		written, err := orgcontext.Save(projectPath, &oc)
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		return mcp.NewToolResultText(fmt.Sprintf("Saved Trojan project context to %s (%d sensitive data categories, %d trust boundaries, %d threat actors). Trojan uses it on the next scan and website test.",
			written, len(oc.SensitiveData), len(oc.TrustBoundaries), len(oc.ThreatActors))), nil
	}
}
