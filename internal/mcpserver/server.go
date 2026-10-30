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

	"github.com/dev-zeph/trojan/internal/ai"
	"github.com/dev-zeph/trojan/internal/normalizer"
)

// Serve starts the Trojan MCP server over stdio for the given project path.
// The AI editor (Claude Code, Cursor, etc.) spawns this process and communicates
// via stdin/stdout using the Model Context Protocol JSON-RPC format. The desktop
// app uses ServeLocal instead (local.go).
func Serve(projectPath string) error {
	// No tier check. Every tool this server exposes reads and writes the local
	// .trojan/scans files -- it makes no network call and spends no tokens, so
	// there is nothing to meter. The AI work it hands off to (explanations, a
	// fix) is metered where it actually happens, in the edge functions.
	//
	// Sign-in is not required either: the findings are already on this machine,
	// and refusing to hand a developer their own scan results would be absurd.
	fixed := func(context.Context, mcp.CallToolRequest) (string, error) { return projectPath, nil }
	return server.ServeStdio(newServer(fixed, false))
}

// localInstructions is sent to the AI tool when it connects to the desktop
// app's server: how to pick a project, how to work with the user, and when to
// offer to refresh Trojan's project context.
const localInstructions = `Trojan is the user's security scanner. It holds findings from scans of their projects and tests of their live websites.

- For code tools, always pass project_path: the absolute path of the project folder you are working in.
- Many users aren't security experts. Explain findings in plain language: what could happen and to whom, before how to fix it.
- After fixing a finding, call verify_fix with its id to prove it is gone instead of just marking it fixed. verify_fix handles both kinds: for a code finding it re-runs the scanner; for a website / pen-test finding it replays the request that proved it (seconds, no credits) and marks it fixed only if the problem is really gone.
- get_all_findings shows code and website findings in one list, each with a source and an id. To re-check several website findings at once (or a whole test) after a fix, use retest_website_findings instead of rerunning start_website_test.
- start_website_test and generate_report spend the user's Trojan credits; say so when you use them. Never set owner_confirmed without the user's explicit yes.
- Trojan's project context (get_project_context) describes what the app does, its sensitive data and trust boundaries, and makes Trojan's testing smarter. If it is missing, offer to draft it from the codebase. After significant changes (new features or routes, a new database or data type, auth changes, new third-party services), ask the user: "Want me to update Trojan's project context to match?" Always show the user what you will save before calling update_project_context.

` + brainInstructions

// brainInstructions tells the AI tool when to use Trojan's code graph,
// rules and memory. Sent by both the stdio and the desktop server.
const brainInstructions = `Trojan keeps a code graph of the whole project (every route, what it calls across files, which tables it reads and writes, where login is checked), the project's security context, and a memory of past findings and decisions. Use it for what reading files one at a time can't show:
- Call get_security_rules BEFORE writing auth, database or API code, and follow its rules.
- Call get_attack_paths after finishing a feature, and when asked which routes are unprotected or write data without a login check.
- Use trace_dataflow before changing a route or function, what_touches before changing a table or sensitive data, get_attack_surface for an overview, get_security_history before reworking a file with past findings.
- After fixing a finding, run verify_fix to prove it is gone.`

// newServer registers Trojan's tools. With perRequest, every tool takes a
// project_path argument and `project` resolves it per call (one server serves
// every project); otherwise `project` returns the one fixed path.
func newServer(project projectFunc, perRequest bool, opts ...server.ServerOption) *server.MCPServer {
	base := []server.ServerOption{
		server.WithDescription("Trojan security scanner — read and act on vulnerability findings in your codebase."),
	}
	if perRequest {
		base = append(base, server.WithInstructions(localInstructions))
	} else {
		base = append(base, server.WithInstructions(brainInstructions))
	}
	opts = append(base, opts...)
	s := server.NewMCPServer(
		"trojan",
		"0.0.1",
		opts...,
	)

	tool := func(name string, o ...mcp.ToolOption) mcp.Tool {
		if perRequest {
			o = append(o, mcp.WithString("project_path",
				mcp.Required(),
				mcp.Description("Absolute path of the project folder you are working in."),
			))
		}
		return mcp.NewTool(name, o...)
	}

	idArg := mcp.WithString("id", mcp.Required(), mcp.Description("The finding id (from get_findings)."))

	// ── Code findings ──
	s.AddTool(
		tool("get_findings",
			mcp.WithDescription("List findings from the project's latest Trojan code scan: id, severity, title, file:line, status, and Trojan's verdict on whether each is real. "+
				"Open findings only by default. Use get_finding for the code and fix steps of one finding."),
			mcp.WithString("min_severity", mcp.Description("Only include this severity and above: critical, high, medium, low or info.")),
			mcp.WithString("status", mcp.Description(`"open" (default) or "all".`)),
			mcp.WithBoolean("confirmed_only", mcp.Description("Only findings Trojan's triage confirmed as real (skips likely false alarms).")),
			mcp.WithBoolean("include_false_positives", mcp.Description("Also show findings Trojan remembers as false alarms (hidden by default).")),
		),
		handleGetFindings(project),
	)
	s.AddTool(
		tool("get_finding",
			mcp.WithDescription("Everything needed to fix one finding: the issue, a plain-English explanation, fix steps, the surrounding source code (~50 lines), language and framework."),
			idArg,
		),
		handleGetFindingWithContext(project),
	)
	s.AddTool(
		tool("get_fixable_findings",
			mcp.WithDescription("All open findings with full fix context in one call, for fixing several at once. Optionally filter by minimum severity."),
			mcp.WithString("min_severity", mcp.Description("Minimum severity to include: critical, high, medium, low, or info. Defaults to all.")),
		),
		handleGetFixableFindings(project),
	)
	s.AddTool(
		tool("verify_fix",
			mcp.WithDescription("After changing code to fix a finding, re-run the Trojan check that found it. If the problem is gone the finding is marked fixed; if not, you get where it still occurs. "+
				"Prefer this over mark_fixed. For website findings, run start_website_test again instead."),
			idArg,
		),
		handleVerifyFix(project),
	)
	s.AddTool(
		tool("mark_fixed",
			mcp.WithDescription("Mark a finding (code or website) as fixed without re-checking. Use verify_fix instead when possible."),
			idArg,
		),
		handleUpdateStatus(project, normalizer.StatusResolved),
	)
	s.AddTool(
		tool("suppress_finding",
			mcp.WithDescription("Hide a finding from future results: for accepted risks or false alarms. Confirm with the user first. "+
				"Trojan remembers the decision, so the same rule in the same file stays hidden after later scans."),
			idArg,
			mcp.WithString("reason", mcp.Description(`Why: e.g. "false alarm: input is a constant", or "user accepts the risk". A reason that says the user accepts it is remembered as an accepted risk, anything else as a false alarm.`)),
		),
		handleUpdateStatus(project, normalizer.StatusSuppressed),
	)
	s.AddTool(
		tool("run_scan",
			mcp.WithDescription("Run a fresh Trojan scan of the whole project (takes a minute or more). Use after larger changes, or for a project Trojan hasn't scanned yet."),
		),
		handleRunScan(project),
	)

	// ── Overviews ──
	s.AddTool(
		tool("get_security_summary",
			mcp.WithDescription("A short overview for answering \"is my app safe?\": open findings by severity, the most urgent ones, personal data the app handles, vulnerable packages, and whether Trojan's project context is set up."),
		),
		handleSecuritySummary(project),
	)
	s.AddTool(
		tool("get_privacy_report",
			mcp.WithDescription("What personal data the project handles (emails, passwords, payment details...), where in the code, and which third-party services it is sent to."),
		),
		handlePrivacyReport(project),
	)
	s.AddTool(
		tool("get_dependency_risks",
			mcp.WithDescription("Packages with known vulnerabilities, their severity, and the version that fixes each. Use to upgrade dependencies."),
		),
		handleDependencyRisks(project),
	)

	// ── Project context ──
	s.AddTool(
		tool("get_project_context",
			mcp.WithDescription("Read Trojan's project context (.trojan/context.yaml): what the app does, what sensitive data it handles, its trust boundaries and who it defends against. Trojan uses it to test the app intentionally."),
		),
		handleGetProjectContext(project),
	)
	s.AddTool(
		tool("update_project_context",
			mcp.WithDescription("Write Trojan's project context from your understanding of the codebase. Replaces the whole context, so read it first and keep what's still true. "+
				"Show the user what you plan to write and get their OK first. "+
				`Shape: {"app":{"name","description"},"sensitive_data":[{"category","description","file_patterns":[globs],"symbol_patterns":[regexes]}],"trust_boundaries":[{"name","description","file_patterns","symbol_patterns"}],"threat_actors":[{"name","description","targets":[boundary names]}]}.`),
			mcp.WithObject("context", mcp.Required(), mcp.Description("The full project context, in the shape above.")),
		),
		handleUpdateProjectContext(project),
	)

	// ── Security brain (code graph, rules, memory) ──
	registerGraphTools(s, tool, project)

	// ── Reports (spend the user's Trojan credits) ──
	s.AddTool(
		tool("generate_report",
			mcp.WithDescription("Generate a Trojan report and save it as Markdown and HTML files the user can open, print to PDF, or send. Spends the user's Trojan credits. "+
				`kind: "security" (code risks, grade and priority fixes), "compliance" (licenses and privacy) or "website" (a live website's pen-test results; pass url).`),
			mcp.WithString("kind", mcp.Required(), mcp.Description(`"security", "compliance" or "website".`)),
			mcp.WithString("url", mcp.Description(`For kind "website": the tested site. Defaults to the most recently tested one.`)),
		),
		handleGenerateReport(project),
	)

	// ── Website tests ── (not tied to a project; take a URL)
	s.AddTool(
		mcp.NewTool("list_website_tests",
			mcp.WithDescription("List the live websites Trojan has tested (penetration tests), newest first, with when each was tested and how many findings are still open."),
		),
		handleListWebsiteTests,
	)
	s.AddTool(
		mcp.NewTool("get_website_findings",
			mcp.WithDescription("Return the findings from Trojan's latest test of a live website (penetration test): what was found, the evidence, and how to fix it. "+
				"The cause is usually in the code of the project you are working in. After fixing, run start_website_test again to confirm."),
			mcp.WithString("url", mcp.Description("The website's URL (or just its host). Defaults to the most recently tested site.")),
		),
		handleGetWebsiteFindings,
	)
	s.AddTool(
		mcp.NewTool("start_website_test",
			mcp.WithDescription("Start Trojan's AI penetration test of a live website or local dev server. Spends the user's Trojan credits and takes several minutes; returns at once. "+
				"Check progress with website_test_status, then read results with get_website_findings. "+
				"Testing a site the user doesn't own is illegal: for a public site Trojan hasn't tested before, ask the user to confirm they own it, then pass owner_confirmed=true."),
			mcp.WithString("url", mcp.Required(), mcp.Description("The site to test, e.g. https://myapp.com or http://localhost:3000.")),
			mcp.WithString("thoroughness", mcp.Description(`"look" (default: only reads pages, changes nothing) or "try" (also submits forms; may leave test entries such as a test sign-up).`)),
			mcp.WithBoolean("owner_confirmed", mcp.Description("Set only after the user has explicitly confirmed they own or may test this site.")),
			mcp.WithString("project_path", mcp.Description("Optional: the site's source code folder, so Trojan can read the code during the test and pinpoint causes.")),
		),
		handleStartWebsiteTest,
	)
	s.AddTool(
		mcp.NewTool("website_test_status",
			mcp.WithDescription("Whether a website test started with start_website_test is still running, finished, or failed."),
			mcp.WithString("url", mcp.Description("The site. Defaults to the most recently started test.")),
		),
		handleWebsiteTestStatus,
	)
	s.AddTool(
		mcp.NewTool("retest_website_findings",
			mcp.WithDescription("Re-check website / pen-test findings in seconds by replaying the exact request that proved each one — no credits, no full rerun. "+
				"Reports each as fixed, still open, or inconclusive, and marks fixed ones resolved. Use after changing code behind a live finding. "+
				"Without ids, re-checks every open finding for the site; pass ids to re-check only those. A finding with no recorded proof (older tests) is inconclusive: run start_website_test instead."),
			mcp.WithString("url", mcp.Description("The tested site (or its host). Defaults to the site holding the given ids, else the most recently tested site.")),
			mcp.WithArray("ids", mcp.Description("Specific website finding IDs to re-check. Omit to re-check all open findings for the site."),
				mcp.Items(map[string]any{"type": "string"})),
		),
		handleRetestWebsiteFindings,
	)
	s.AddTool(
		tool("get_all_findings",
			mcp.WithDescription("One list of every open finding, code and website together, each with a source (\"code\" or \"website\") and a stable id you can pass to verify_fix. "+
				"Use this to see the whole picture: the website test's findings are included alongside the code scan's, so you don't have to check two places."),
			mcp.WithString("min_severity", mcp.Description("Only include this severity and above: critical, high, medium, low or info.")),
			mcp.WithString("status", mcp.Description(`"open" (default) or "all".`)),
		),
		handleGetAllFindings(project),
	)

	return s
}

// --- handlers ---

func handleGetFindings(project projectFunc) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		projectPath, err := project(ctx, req)
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		scan, err := loadLatestScan(projectPath)
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}

		minRank := severityRank[normalizer.Severity(strings.ToLower(req.GetString("min_severity", "info")))]
		all := strings.EqualFold(req.GetString("status", "open"), "all")
		confirmedOnly := req.GetBool("confirmed_only", false)
		isFP := rememberedFalsePositives(projectPath, req.GetBool("include_false_positives", false))

		type row struct {
			ID       string `json:"id"`
			Source   string `json:"source"`
			Severity string `json:"severity"`
			Title    string `json:"title"`
			Location string `json:"location,omitempty"`
			Status   string `json:"status"`
			Verdict  string `json:"verdict,omitempty"`
			Exposure string `json:"exposure,omitempty"`
			priority int
		}
		rows := []row{}
		hiddenFP := 0
		for _, f := range scan.Findings {
			if (!all && f.Status != normalizer.StatusOpen) || severityRank[f.Severity] < minRank {
				continue
			}
			if confirmedOnly && f.Verdict != "confirmed" {
				continue
			}
			if isFP(f) {
				hiddenFP++
				continue
			}
			loc := f.FilePath
			if f.LineNumber > 0 {
				loc = fmt.Sprintf("%s:%d", f.FilePath, f.LineNumber)
			}
			r := row{ID: f.ID, Source: "code", Severity: string(f.Severity), Title: f.Title, Location: loc, Status: string(f.Status), Verdict: f.Verdict}
			if f.Reach != nil {
				r.Exposure, r.priority = exposureSummary(f.Reach), f.Reach.Priority
			}
			rows = append(rows, r)
		}
		// Severity first; within a severity, code a public route reaches
		// without login (and sensitive code) comes first.
		sort.SliceStable(rows, func(i, j int) bool {
			si, sj := severityRank[normalizer.Severity(rows[i].Severity)], severityRank[normalizer.Severity(rows[j].Severity)]
			if si != sj {
				return si > sj
			}
			return rows[i].priority > rows[j].priority
		})

		out, err := json.MarshalIndent(map[string]any{
			"project":                projectPath,
			"scanned_at":             scan.Timestamp,
			"total":                  len(scan.Findings),
			"shown":                  len(rows),
			"hidden_false_positives": hiddenFP,
			"findings":               rows,
		}, "", "  ")
		if err != nil {
			return mcp.NewToolResultError("failed to serialize findings"), nil
		}
		return mcp.NewToolResultText(string(out)), nil
	}
}

func handleUpdateStatus(project projectFunc, status normalizer.Status) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		id, err := req.RequireString("id")
		if err != nil {
			return mcp.NewToolResultError("missing required parameter: id"), nil
		}

		// The ID may belong to the project's code scan or to a website test, so
		// look in the project first, then every tested site.
		var dirs []string
		projectPath, perr := project(ctx, req)
		if perr == nil {
			dirs = append(dirs, projectPath)
		}
		dirs = append(dirs, normalizer.WebsiteSiteDirs()...)

		for _, dir := range dirs {
			scan, err := loadLatestScan(dir)
			if err != nil {
				continue
			}
			for i, f := range scan.Findings {
				if f.ID != id {
					continue
				}
				scan.Findings[i].Status = status
				if err := saveLatestScan(dir, scan); err != nil {
					return mcp.NewToolResultError("failed to save updated scan: " + err.Error()), nil
				}
				// Code findings are remembered so later scans and agents know
				// the decision (website findings have no project to hold it).
				if perr == nil && dir == projectPath {
					recordStatusMemory(projectPath, f, status, req.GetString("reason", ""))
				}
				return mcp.NewToolResultText(fmt.Sprintf("finding %s marked as %s", id, status)), nil
			}
		}
		if perr != nil {
			return mcp.NewToolResultError(perr.Error()), nil
		}
		return mcp.NewToolResultError(fmt.Sprintf("finding %q not found", id)), nil
	}
}

func handleRunScan(project projectFunc) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		projectPath, err := project(ctx, req)
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}

		// Re-run this same binary rather than `trojan` from PATH: the desktop
		// app's copy isn't on PATH. scan-once scans, saves and exits.
		exe, err := os.Executable()
		if err != nil {
			return mcp.NewToolResultError("could not locate the Trojan binary: " + err.Error()), nil
		}
		cmd := exec.CommandContext(ctx, exe, "mcp", "scan-once", projectPath)
		cmd.Dir = projectPath
		if out, err := cmd.CombinedOutput(); err != nil {
			return mcp.NewToolResultError("scan failed: " + err.Error() + "\n" + string(out)), nil
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

// --- fix-context handlers ---

// findingContext is the enriched payload returned by the context-aware tools.
type findingContext struct {
	ID              string   `json:"id"`
	Title           string   `json:"title"`
	Severity        string   `json:"severity"`
	Scanner         string   `json:"scanner"`
	Category        string   `json:"category"`
	RuleID          string   `json:"rule_id"`
	Status          string   `json:"status"`
	FilePath        string   `json:"file_path"`
	LineNumber      int      `json:"line_number"`
	CodeSnippet     string   `json:"code_snippet"`
	SurroundingCode string   `json:"surrounding_code"`
	Language        string   `json:"language"`
	Framework       string   `json:"framework"`
	ProjectType     string   `json:"project_type"`
	RawMessage      string   `json:"raw_message"`
	Simply          string   `json:"simply,omitempty"`
	Actions         []string `json:"actions,omitempty"`
	FixDiff         string   `json:"fix_diff,omitempty"`
	Verdict         string   `json:"verdict,omitempty"`
	VerdictReason   string   `json:"verdict_reason,omitempty"`
}

func buildFindingContext(f normalizer.Finding, projectPath string) findingContext {
	// Enrich with context if not already present
	lang := f.Language
	if lang == "" {
		lang = ai.DetectLanguage(f.FilePath)
	}
	framework := f.Framework
	if framework == "" {
		framework = ai.DetectFramework(projectPath)
	}
	projectType := f.ProjectType
	if projectType == "" {
		projectType = ai.DetectProjectTypeName(projectPath)
	}

	surrounding := f.SurroundingCode
	if surrounding == "" {
		fullPath := f.FilePath
		if !filepath.IsAbs(fullPath) {
			fullPath = filepath.Join(projectPath, fullPath)
		}
		surrounding = ai.ExtractSurroundingCode(fullPath, f.LineNumber, 25)
	}

	return findingContext{
		ID:              f.ID,
		Title:           f.Title,
		Severity:        string(f.Severity),
		Scanner:         f.Scanner,
		Category:        f.Category,
		RuleID:          f.RuleID,
		Status:          string(f.Status),
		FilePath:        f.FilePath,
		LineNumber:      f.LineNumber,
		CodeSnippet:     f.CodeSnippet,
		SurroundingCode: surrounding,
		Language:        lang,
		Framework:       framework,
		ProjectType:     projectType,
		RawMessage:      f.RawMessage,
		Simply:          f.Simply,
		Actions:         f.Actions,
		FixDiff:         f.FixDiff,
		Verdict:         f.Verdict,
		VerdictReason:   f.VerdictReason,
	}
}

func handleGetFindingWithContext(project projectFunc) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		projectPath, err := project(ctx, req)
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}

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
				fc := buildFindingContext(f, projectPath)
				out, err := json.MarshalIndent(fc, "", "  ")
				if err != nil {
					return mcp.NewToolResultError("failed to serialize finding context"), nil
				}
				return mcp.NewToolResultText(string(out)), nil
			}
		}
		return mcp.NewToolResultError(fmt.Sprintf("finding %q not found", id)), nil
	}
}

var severityRank = map[normalizer.Severity]int{
	normalizer.SeverityCritical: 4,
	normalizer.SeverityHigh:     3,
	normalizer.SeverityMedium:   2,
	normalizer.SeverityLow:      1,
	normalizer.SeverityInfo:     0,
}

func handleGetFixableFindings(project projectFunc) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		projectPath, err := project(ctx, req)
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}

		scan, err := loadLatestScan(projectPath)
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}

		minRank := 0
		if minSev, _ := req.RequireString("min_severity"); minSev != "" {
			if r, ok := severityRank[normalizer.Severity(strings.ToLower(minSev))]; ok {
				minRank = r
			}
		}

		var results []findingContext
		for _, f := range scan.Findings {
			if f.Status != normalizer.StatusOpen {
				continue
			}
			if severityRank[f.Severity] < minRank {
				continue
			}
			results = append(results, buildFindingContext(f, projectPath))
		}

		summary := struct {
			Total    int              `json:"total"`
			Findings []findingContext `json:"findings"`
		}{
			Total:    len(results),
			Findings: results,
		}

		out, err := json.MarshalIndent(summary, "", "  ")
		if err != nil {
			return mcp.NewToolResultError("failed to serialize findings"), nil
		}
		return mcp.NewToolResultText(string(out)), nil
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
