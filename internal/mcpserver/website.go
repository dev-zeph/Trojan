package mcpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/mark3labs/mcp-go/mcp"

	"github.com/dev-zeph/trojan/internal/config"
	"github.com/dev-zeph/trojan/internal/dast"
	"github.com/dev-zeph/trojan/internal/normalizer"
)

// ── Website test tools ───────────────────────────────────────────────────────
// Results live under ~/.trojan/website-tests (normalizer.SaveWebsiteTest).

type websiteSummary struct {
	URL        string    `json:"url"`
	TestedAt   time.Time `json:"tested_at"`
	Findings   int       `json:"findings"`
	OpenIssues int       `json:"open"`
}

func handleListWebsiteTests(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	recordActivity(clientName(ctx), "")
	var out []websiteSummary
	for _, dir := range normalizer.WebsiteSiteDirs() {
		scan, err := loadLatestScan(dir)
		if err != nil {
			continue
		}
		out = append(out, websiteSummary{scan.ProjectPath, scan.Timestamp, len(scan.Findings), countOpen(scan.Findings)})
	}
	if len(out) == 0 {
		return mcp.NewToolResultText("No website tests yet. Test a live site from the Trojan app (Live URL Testing) first."), nil
	}
	data, _ := json.MarshalIndent(out, "", "  ")
	return mcp.NewToolResultText(string(data)), nil
}

func handleGetWebsiteFindings(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	recordActivity(clientName(ctx), "")
	dirs := normalizer.WebsiteSiteDirs()
	if len(dirs) == 0 {
		return mcp.NewToolResultError("No website tests yet. Test a live site from the Trojan app (Live URL Testing) first."), nil
	}

	dir := dirs[0]
	if want := strings.TrimSpace(req.GetString("url", "")); want != "" {
		dir = ""
		if !strings.Contains(want, "://") {
			want = "https://" + want
		}
		if d, err := normalizer.WebsiteDir(want); err == nil {
			for _, cand := range dirs {
				// Match on host; tolerate a missing or different port/scheme.
				if cand == d || strings.HasPrefix(filepath.Base(cand), filepath.Base(d)) {
					dir = cand
					break
				}
			}
		}
		if dir == "" {
			return mcp.NewToolResultError(fmt.Sprintf("Trojan hasn't tested %s yet. Call list_website_tests to see tested sites.", want)), nil
		}
	}

	scan, err := loadLatestScan(dir)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	result := struct {
		URL      string               `json:"url"`
		TestedAt time.Time            `json:"tested_at"`
		Findings []normalizer.Finding `json:"findings"`
	}{scan.ProjectPath, scan.Timestamp, scan.Findings}
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return mcp.NewToolResultError("failed to serialize findings"), nil
	}
	return mcp.NewToolResultText(string(data)), nil
}

// ── Starting website tests from an AI tool ───────────────────────────────────

// websiteRun is a site's most recent test started through MCP, kept in
// <site dir>/last-run.json.
type websiteRun struct {
	URL        string     `json:"url"`
	PID        int        `json:"pid"`
	State      string     `json:"state"` // running | finished | failed
	StartedAt  time.Time  `json:"started_at"`
	FinishedAt *time.Time `json:"finished_at,omitempty"`
	ExitCode   int        `json:"exit_code,omitempty"`
}

func runFile(siteDir string) string { return filepath.Join(siteDir, "last-run.json") }

func loadRun(siteDir string) *websiteRun {
	data, err := os.ReadFile(runFile(siteDir))
	if err != nil {
		return nil
	}
	var r websiteRun
	if json.Unmarshal(data, &r) != nil {
		return nil
	}
	// The server may have restarted mid-run; trust the process table.
	if r.State == "running" && !processAlive(r.PID) {
		r.State = "failed"
	}
	return &r
}

func saveRun(siteDir string, r *websiteRun) {
	if data, err := json.MarshalIndent(r, "", "  "); err == nil {
		os.WriteFile(runFile(siteDir), data, 0600) //nolint:errcheck
	}
}

func processAlive(pid int) bool {
	p, err := os.FindProcess(pid)
	return err == nil && p.Signal(syscall.Signal(0)) == nil
}

// normalizeSiteURL adds a scheme when the AI passes a bare host:
// http for local dev servers, https otherwise.
func normalizeSiteURL(raw string) string {
	raw = strings.TrimSpace(raw)
	if strings.Contains(raw, "://") {
		return raw
	}
	host := strings.Split(raw, "/")[0]
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	if dast.IsLocalHost(host) {
		return "http://" + raw
	}
	return "https://" + raw
}

func handleStartWebsiteTest(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	recordActivity(clientName(ctx), "")
	target := normalizeSiteURL(req.GetString("url", ""))
	if target == "" || target == "https://" {
		return mcp.NewToolResultError("missing required parameter: url"), nil
	}

	email := ""
	if cfg, err := config.LoadConfig(); err == nil {
		email = cfg.UserEmail
	}
	allowed, _, _, domain, err := dast.GateStatus(target, email)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	ownerConfirmed := req.GetBool("owner_confirmed", false)
	if !allowed && !ownerConfirmed {
		return mcp.NewToolResultError(fmt.Sprintf("Trojan hasn't been told the user owns %s. Ask them: \"Do you own %s, or have permission to test it?\" "+
			"Only if they say yes, call start_website_test again with owner_confirmed=true. Testing a site you don't own is illegal.", domain, domain)), nil
	}

	siteDir, err := normalizer.WebsiteDir(target)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	if err := os.MkdirAll(siteDir, 0700); err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	if r := loadRun(siteDir); r != nil && r.State == "running" {
		return mcp.NewToolResultText(fmt.Sprintf("A test of %s is already running (started %s). Check it with website_test_status.", r.URL, r.StartedAt.Format(time.Kitchen))), nil
	}

	tier := "passive"
	thorough := strings.EqualFold(req.GetString("thoroughness", "look"), "try")
	if thorough {
		tier = "safe-active"
	}
	args := []string{"dast", target, "--agentic", "--desktop", "--exit-when-done", "--tier", tier, "--env", "production"}
	if thorough {
		args = append(args, "--accept-side-effects")
	}
	if !allowed {
		args = append(args, "--owner-confirmed")
	}

	exe, err := os.Executable()
	if err != nil {
		return mcp.NewToolResultError("could not locate the Trojan binary: " + err.Error()), nil
	}
	cmd := exec.Command(exe, args...)
	cmd.Dir = siteDir
	// With the site's source folder, the agent can read the code (grey-box).
	if p := expandHome(strings.TrimSpace(req.GetString("project_path", ""))); p != "" {
		if info, err := os.Stat(p); err == nil && info.IsDir() {
			cmd.Dir = p
			cmd.Args = append(cmd.Args, "--grey-box")
		}
	}
	logf, err := os.Create(filepath.Join(siteDir, "last-run.log"))
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	cmd.Stdout, cmd.Stderr = logf, logf
	if err := cmd.Start(); err != nil {
		logf.Close()
		return mcp.NewToolResultError("could not start the test: " + err.Error()), nil
	}

	run := &websiteRun{URL: target, PID: cmd.Process.Pid, State: "running", StartedAt: time.Now().UTC()}
	saveRun(siteDir, run)
	go func() {
		err := cmd.Wait()
		logf.Close()
		now := time.Now().UTC()
		run.FinishedAt, run.State = &now, "finished"
		if err != nil {
			run.State, run.ExitCode = "failed", cmd.ProcessState.ExitCode()
		}
		saveRun(siteDir, run)
	}()

	mode := "look only: Trojan reads pages and changes nothing"
	if thorough {
		mode = "try to get in: Trojan also submits forms and may leave test entries"
	}
	return mcp.NewToolResultText(fmt.Sprintf("Started Trojan's AI penetration test of %s (%s). It uses the user's Trojan credits and usually takes 5 to 15 minutes. "+
		"Check progress with website_test_status, then read results with get_website_findings.", target, mode)), nil
}

func handleWebsiteTestStatus(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	recordActivity(clientName(ctx), "")
	root, err := normalizer.WebsiteTestsDir()
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	var siteDir string
	if u := strings.TrimSpace(req.GetString("url", "")); u != "" {
		siteDir, _ = normalizer.WebsiteDir(normalizeSiteURL(u))
	} else {
		// Most recently started run across all sites.
		var newest time.Time
		entries, _ := os.ReadDir(root)
		for _, e := range entries {
			d := filepath.Join(root, e.Name())
			if r := loadRun(d); r != nil && r.StartedAt.After(newest) {
				newest, siteDir = r.StartedAt, d
			}
		}
	}
	r := (*websiteRun)(nil)
	if siteDir != "" {
		r = loadRun(siteDir)
	}
	if r == nil {
		return mcp.NewToolResultText("No website test has been started from an AI tool for that site. Start one with start_website_test."), nil
	}

	switch r.State {
	case "running":
		return mcp.NewToolResultText(fmt.Sprintf("Still running: %s, started %s ago. Check again in a few minutes.", r.URL, time.Since(r.StartedAt).Round(time.Second))), nil
	case "finished":
		return mcp.NewToolResultText(fmt.Sprintf("Finished: %s. Read the results with get_website_findings(url=%q).", r.URL, r.URL)), nil
	}
	tail := ""
	if data, err := os.ReadFile(filepath.Join(siteDir, "last-run.log")); err == nil {
		lines := strings.Split(strings.TrimSpace(string(data)), "\n")
		if len(lines) > 15 {
			lines = lines[len(lines)-15:]
		}
		tail = strings.Join(lines, "\n")
	}
	return mcp.NewToolResultError(fmt.Sprintf("The test of %s stopped without finishing. Last output:\n%s", r.URL, tail)), nil
}
