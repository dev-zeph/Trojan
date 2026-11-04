package mcpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
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
	// State and Note appear only for runs that have no saved scan yet — one
	// still running, or one that failed. A finished test leaves them empty.
	State string `json:"state,omitempty"`
	Note  string `json:"note,omitempty"`
}

func handleListWebsiteTests(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	recordActivity(clientName(ctx), "")
	var out []websiteSummary
	seen := map[string]bool{}
	for _, dir := range normalizer.WebsiteSiteDirs() {
		scan, err := loadLatestScan(dir)
		if err != nil {
			continue
		}
		out = append(out, websiteSummary{URL: scan.ProjectPath, TestedAt: scan.Timestamp, Findings: len(scan.Findings), OpenIssues: countOpen(scan.Findings)})
		seen[scan.ProjectPath] = true
	}
	// Also surface MCP-started runs that are still running or failed: these
	// write no scan, so the loop above never sees them, and without this a
	// failed or in-progress test is invisible here (it is visible in
	// website_test_status — the two must not disagree).
	if root, err := normalizer.WebsiteTestsDir(); err == nil {
		entries, _ := os.ReadDir(root)
		for _, e := range entries {
			r := loadRun(filepath.Join(root, e.Name()))
			if r == nil || seen[r.URL] || (r.State != "running" && r.State != "failed") {
				continue
			}
			out = append(out, websiteSummary{URL: r.URL, TestedAt: r.StartedAt, State: r.State, Note: r.Reason})
			seen[r.URL] = true
		}
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
		// Coerce a bare host the same way start_website_test does (http for
		// localhost, https otherwise), so a site tested over http still matches.
		want = normalizeSiteURL(want)
		if d, err := normalizer.WebsiteDir(want); err == nil {
			// If the most recent MCP-started run for this site failed or is
			// still running, say so plainly — a failed run writes no scan, so
			// without this the tool wrongly reports "hasn't tested yet".
			if r := loadRun(d); r != nil {
				switch r.State {
				case "running":
					return mcp.NewToolResultError(fmt.Sprintf("The test of %s is still running. Check website_test_status, then read findings once it finishes.", r.URL)), nil
				case "failed":
					reason := r.Reason
					if reason == "" {
						reason = "the test did not finish."
					}
					return mcp.NewToolResultError(fmt.Sprintf("The last test of %s failed, so there are no findings: %s", r.URL, reason)), nil
				}
			}
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
		URL      string           `json:"url"`
		TestedAt time.Time        `json:"tested_at"`
		Findings []websiteFinding `json:"findings"`
	}{scan.ProjectPath, scan.Timestamp, toWebsiteFindings(scan.Findings)}
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return mcp.NewToolResultError("failed to serialize findings"), nil
	}
	return mcp.NewToolResultText(string(data)), nil
}

// websiteFinding is a stored website finding as get_website_findings returns
// it: every Finding field (FilePath stays the probed URL for older clients;
// url, source_file and source_line are on Finding) plus a ready-to-use
// "location" ("app/api/admin/customers/route.ts:12") when Trojan placed the
// finding in the project's source.
type websiteFinding struct {
	normalizer.Finding
	Location string `json:"location,omitempty"`
}

func toWebsiteFindings(fs []normalizer.Finding) []websiteFinding {
	out := make([]websiteFinding, len(fs))
	for i, f := range fs {
		if f.URL == "" && f.Category == "dast" {
			f.URL = f.FilePath // results saved before url existed
		}
		out[i] = websiteFinding{Finding: f, Location: sourceLocation(f)}
	}
	return out
}

// sourceLocation renders a website finding's source anchor as "file:line"
// (or just "file" when the line is unknown); "" when there is none.
func sourceLocation(f normalizer.Finding) string {
	if f.SourceFile == "" {
		return ""
	}
	if f.SourceLine > 0 {
		return fmt.Sprintf("%s:%d", f.SourceFile, f.SourceLine)
	}
	return f.SourceFile
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
	// Reason explains a failed run in plain language (e.g. the engine was not
	// authorized, or crashed). Empty for running/finished runs. Set by
	// finalizeRun, which inspects the engine's own PENTEST_END outcome — the
	// engine can exit 0 while reporting an internal error, so exit code alone
	// is not enough.
	Reason string `json:"reason,omitempty"`
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

var ansiRe = regexp.MustCompile(`\x1b\[[0-9;]*m`)

// lastLogActivity returns the most recent non-empty line of a run's log, with
// terminal color codes stripped, so a running test can show real progress
// ("Latest activity: crawling /admin ...") instead of only elapsed time.
func lastLogActivity(siteDir string) string {
	data, err := os.ReadFile(filepath.Join(siteDir, "last-run.log"))
	if err != nil {
		return ""
	}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		s := strings.TrimSpace(ansiRe.ReplaceAllString(lines[i], ""))
		if s != "" {
			if len(s) > 200 {
				s = s[:200] + "…"
			}
			return s
		}
	}
	return ""
}

// handleWebsiteTestDoctor reports whether the environment is ready to run a
// website test, so an agent can check readiness BEFORE spending tokens. It
// makes no network calls and spends nothing.
func handleWebsiteTestDoctor(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	recordActivity(clientName(ctx), "")
	type check struct {
		Check  string `json:"check"`
		OK     bool   `json:"ok"`
		Detail string `json:"detail"`
	}
	var checks []check

	cfg, _ := config.LoadConfig()
	signedIn := cfg != nil && strings.TrimSpace(cfg.AccessToken) != ""
	who := "not signed in — sign in via the Trojan app (or `trojan login`), then retry"
	if signedIn {
		who = "signed in as " + cfg.UserEmail
	}
	checks = append(checks, check{"signed_in", signedIn, who})

	engineOK := false
	engineDetail := "could not locate the Trojan engine binary"
	if exe, err := os.Executable(); err == nil {
		if fi, statErr := os.Stat(exe); statErr == nil && !fi.IsDir() {
			engineOK, engineDetail = true, "pen-test engine present at "+exe
		} else {
			engineDetail = "pen-test engine missing at " + exe + " — reinstall or rebuild the Trojan app, then retry"
		}
	}
	checks = append(checks, check{"engine_binary", engineOK, engineDetail})

	out := struct {
		Ready  bool    `json:"ready"`
		Checks []check `json:"checks"`
		Note   string  `json:"note"`
	}{
		Ready:  signedIn && engineOK,
		Checks: checks,
		Note:   "A website test is metered by the account's Trojan token balance, not a plan. If these checks pass but a test still fails with a 401, the sign-in has expired — sign in again.",
	}
	data, _ := json.MarshalIndent(out, "", "  ")
	return mcp.NewToolResultText(string(data)), nil
}

// finalizeRun decides a completed run's true state. The pen-test engine can
// exit 0 while its agentic phase failed — it writes PENTEST_END
// {"outcome":"error"} to the log and exits cleanly — so a non-error exit code
// is not proof of success. finalizeRun inspects the run log for the engine's
// own outcome and for well-known auth/credit failures, and returns the state
// plus a plain-language reason so status/findings can surface the real cause.
func finalizeRun(siteDir string, waitErr error, exitCode int) (state, reason string) {
	log := ""
	if data, err := os.ReadFile(filepath.Join(siteDir, "last-run.log")); err == nil {
		log = string(data)
	}
	low := strings.ToLower(log)

	switch {
	// Authorization wall on the hosted pen-test backend. Agentic DAST is
	// metered by token balance, not a plan, so a 401 means the sign-in was
	// rejected — expired or invalid credentials — not a missing entitlement.
	case strings.Contains(low, "status 401"), strings.Contains(low, "unauthorized"):
		return "failed", "the pen-test backend rejected the account's sign-in (401). The login has most likely expired or is invalid — sign in to Trojan again, then retry. (Agentic DAST is metered by your Trojan token balance, so this is not a plan limit.)"
	// The engine ran but the token balance could not cover the run.
	case strings.Contains(low, "status 402"), strings.Contains(low, "payment required"),
		strings.Contains(low, "insufficient tokens"), strings.Contains(low, "insufficient balance"):
		return "failed", "the run stopped because the account's Trojan token balance could not cover it. Top up tokens, then retry."
	// The engine reported its own error outcome (it may still have exited 0).
	case strings.Contains(log, `"outcome":"error"`), strings.Contains(log, `"outcome": "error"`):
		return "failed", "the pen-test engine reported an error and produced no findings. See the last output with website_test_status."
	// The process itself died abnormally.
	case waitErr != nil:
		return "failed", fmt.Sprintf("the pen-test engine exited abnormally (code %d). See the last output with website_test_status.", exitCode)
	}
	return "finished", ""
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

	// Preflight: a test shells out to the hosted pen-test backend and is
	// metered by the account's Trojan token balance, so it needs a sign-in.
	// Fail here, before anything is charged, rather than after a backend 401.
	cfg, _ := config.LoadConfig()
	if cfg == nil || strings.TrimSpace(cfg.AccessToken) == "" {
		return mcp.NewToolResultError("Not signed in to Trojan, so the pen-test backend can't be reached (nothing was charged). Sign in via the Trojan app (or run `trojan login`), then retry."), nil
	}
	email := cfg.UserEmail
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
	// Preflight: the test runs by executing this same binary with the `dast`
	// subcommand. If that file is gone (app bundle moved or cleaned while the
	// server kept running), fork/exec fails deep in the run; catch it here so
	// nothing is charged and the message is actionable.
	if fi, statErr := os.Stat(exe); statErr != nil || fi.IsDir() {
		return mcp.NewToolResultError(fmt.Sprintf("The Trojan pen-test engine is missing at %s, so no test was started (nothing was charged). This happens when the desktop app bundle was moved or cleaned while the server kept running. Reinstall or rebuild the Trojan app, then retry.", exe)), nil
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
		run.FinishedAt = &now
		run.ExitCode = cmd.ProcessState.ExitCode()
		run.State, run.Reason = finalizeRun(siteDir, err, run.ExitCode)
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
		msg := fmt.Sprintf("Still running: %s, started %s ago.", r.URL, time.Since(r.StartedAt).Round(time.Second))
		if act := lastLogActivity(siteDir); act != "" {
			msg += " Latest activity: " + act
		}
		return mcp.NewToolResultText(msg + " Check again in a few minutes."), nil
	case "finished":
		return mcp.NewToolResultText(fmt.Sprintf("Finished: %s. Read the results with get_website_findings(url=%q).", r.URL, r.URL)), nil
	}
	reason := r.Reason
	if reason == "" {
		reason = "the test stopped without finishing."
	}
	tail := ""
	if data, err := os.ReadFile(filepath.Join(siteDir, "last-run.log")); err == nil {
		lines := strings.Split(strings.TrimSpace(string(data)), "\n")
		if len(lines) > 15 {
			lines = lines[len(lines)-15:]
		}
		tail = strings.Join(lines, "\n")
	}
	return mcp.NewToolResultError(fmt.Sprintf("The test of %s failed: %s\n\nLast output:\n%s", r.URL, reason, tail)), nil
}
