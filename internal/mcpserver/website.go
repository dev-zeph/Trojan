package mcpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"

	"github.com/dev-zeph/trojan/internal/ai"
	"github.com/dev-zeph/trojan/internal/config"
	"github.com/dev-zeph/trojan/internal/dast"
	"github.com/dev-zeph/trojan/internal/dast/agent"
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

	payload, err := websiteFindingsPayload(dir, websiteProjectPath(req, dir))
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return mcp.NewToolResultError("failed to serialize findings"), nil
	}
	return mcp.NewToolResultText(string(data)), nil
}

// websiteProjectPath is the site's source folder: the project_path the caller
// passed, else the one its last MCP-started run was given. "" when neither
// names a real folder.
func websiteProjectPath(req mcp.CallToolRequest, siteDir string) string {
	p := expandHome(strings.TrimSpace(req.GetString("project_path", "")))
	if p == "" {
		if r := loadRun(siteDir); r != nil {
			p = r.ProjectPath
		}
	}
	if p == "" {
		return ""
	}
	if info, err := os.Stat(p); err != nil || !info.IsDir() {
		return ""
	}
	return filepath.Clean(p)
}

// websiteFindingsResult is get_website_findings' payload, also returned by a
// blocking start_website_test / website_test_status once the run finishes.
type websiteFindingsResult struct {
	URL         string            `json:"url"`
	TestedAt    time.Time         `json:"tested_at"`
	ProjectPath string            `json:"project_path,omitempty"`
	Findings    []websiteFinding  `json:"findings"`
	Coverage    *coverageManifest `json:"coverage,omitempty"`
	NextSteps   []string          `json:"next_steps"`
}

func websiteFindingsPayload(siteDir, projectPath string) (*websiteFindingsResult, error) {
	scan, err := loadLatestScan(siteDir)
	if err != nil {
		return nil, err
	}
	out := &websiteFindingsResult{
		URL:         scan.ProjectPath,
		TestedAt:    scan.Timestamp,
		ProjectPath: projectPath,
		Findings:    toWebsiteFindings(scan.Findings, newCorrelator(projectPath)),
	}
	// Coverage comes from the run log, which only exists for MCP-started runs
	// and describes the latest one: attach it only when that run is the one
	// these findings came from (it finished within a minute of the save).
	if r := loadRun(siteDir); r != nil && r.State == "finished" && r.FinishedAt != nil {
		if d := r.FinishedAt.Sub(scan.Timestamp); d > -time.Minute && d < time.Minute {
			if p, ok := readRunProgress(siteDir); ok {
				cov := p.coverage(projectPath)
				out.Coverage = &cov
			}
		}
	}
	out.NextSteps = websiteNextSteps(out)
	return out, nil
}

// websiteNextSteps tells the agent what to do with these findings, pointing at
// the cheap per-finding retest instead of a full (paid, ~10 min) rerun.
func websiteNextSteps(r *websiteFindingsResult) []string {
	var open []string
	for _, f := range r.Findings {
		if f.Status == normalizer.StatusOpen && f.Verdict != "likely_fp" {
			open = append(open, fmt.Sprintf("%q", f.ID))
		}
	}
	steps := []string{}
	if len(open) > 0 {
		steps = append(steps, fmt.Sprintf("After fixing, prove it with retest_website_findings(url=%q, ids=[%s]): it replays each finding's recorded attack in seconds, spends no credits, and marks fixed ones resolved. Do not rerun start_website_test just to check a fix.", r.URL, strings.Join(open, ", ")))
	}
	if r.ProjectPath == "" {
		steps = append(steps, "Pass project_path (the site's source folder) to place each finding on its handler's file:line and link the matching code findings (related_findings).")
	}
	if r.Coverage != nil && len(r.Coverage.RoutesNotReached) > 0 {
		steps = append(steps, fmt.Sprintf("%d route(s) in the code were never reached by the live test (coverage.routes_not_reached); the code findings for them are your only signal.", len(r.Coverage.RoutesNotReached)))
	}
	return steps
}

// websiteFinding is a stored website finding as get_website_findings returns
// it: every Finding field (FilePath stays the probed URL for older clients;
// url, source_file and source_line are on Finding) plus a ready-to-use
// "location" ("app/api/admin/customers/route.ts:12") when Trojan placed the
// finding in the project's source, and the code-scan findings in the same
// handler when the site's project folder is known.
type websiteFinding struct {
	normalizer.Finding
	Location        string           `json:"location,omitempty"`
	RelatedFindings []relatedFinding `json:"related_findings,omitempty"`
	CodeScanNote    string           `json:"code_scan_note,omitempty"`
}

// toWebsiteFindings shapes stored findings for output. c (nil when the site's
// source folder is unknown) places live findings on their handler and links
// related code findings; stored results are not modified.
func toWebsiteFindings(fs []normalizer.Finding, c *correlator) []websiteFinding {
	out := make([]websiteFinding, len(fs))
	for i, f := range fs {
		if f.URL == "" && f.Category == "dast" {
			f.URL = f.FilePath // results saved before url existed
		}
		wf := websiteFinding{}
		if c != nil && f.Category == "dast" {
			c.place(&f)
			wf.RelatedFindings = c.related(f)
			wf.CodeScanNote = c.codeScanNote(f, wf.RelatedFindings)
		}
		wf.Finding, wf.Location = f, sourceLocation(f)
		out[i] = wf
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
	// ProjectPath is the source folder passed to start_website_test, kept so
	// status/findings can map coverage and correlate with the code scan later
	// without the agent passing it again.
	ProjectPath string `json:"project_path,omitempty"`
	// PrevDurationSec is how long this site's previous finished run took, for
	// time estimates (last-run.json only ever holds the latest run).
	PrevDurationSec int `json:"prev_duration_sec,omitempty"`
}

// duration is how long a finished run took (0 if unknown).
func (r *websiteRun) duration() time.Duration {
	if r == nil || r.FinishedAt == nil {
		return 0
	}
	return r.FinishedAt.Sub(r.StartedAt)
}

// activeRuns maps a site dir to a channel closed once this server process has
// recorded that run's final state, so a blocking wait never reads the brief
// window between the engine exiting and finalizeRun saving its verdict.
var activeRuns sync.Map // siteDir -> chan struct{}

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

// typicalTestTokens is the usual Trojan-token cost of one agentic pen test
// (the figure `trojan balance` warns against). Actual use is metered and grows
// with the size of the site.
const typicalTestTokens = 365

// doctorCheck is one line of website_test_doctor's report. Warn-only checks
// (OK true, Warning set) don't block a run but are worth reading.
type doctorCheck struct {
	Check   string `json:"check"`
	OK      bool   `json:"ok"`
	Detail  string `json:"detail"`
	Warning bool   `json:"warning,omitempty"`
}

// doctorHTTPClient is swapped in tests.
var doctorHTTPClient = &http.Client{Timeout: 10 * time.Second}

// handleWebsiteTestDoctor reports whether a website test is ready to run, so an
// agent can check BEFORE spending tokens. Without a url it checks the local
// setup only. With a url it also checks the site answers, logs in with each
// saved test account (the engine aborts the whole run if one fails), and
// estimates cost and time. It spends no Trojan tokens; it sends a handful of
// requests to the target and one to Trojan's account service.
func handleWebsiteTestDoctor(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	recordActivity(clientName(ctx), "")
	var checks []doctorCheck
	add := func(c doctorCheck) { checks = append(checks, c) }

	cfg, _ := config.LoadConfig()
	signedIn := cfg != nil && strings.TrimSpace(cfg.AccessToken) != ""
	who := "not signed in: sign in via the Trojan app (or `trojan login`), then retry"
	if signedIn {
		who = "signed in as " + cfg.UserEmail
	}
	add(doctorCheck{Check: "signed_in", OK: signedIn, Detail: who})

	engineOK := false
	engineDetail := "could not locate the Trojan engine binary"
	if exe, err := os.Executable(); err == nil {
		if fi, statErr := os.Stat(exe); statErr == nil && !fi.IsDir() {
			engineOK, engineDetail = true, "pen-test engine present at "+exe
		} else {
			engineDetail = "pen-test engine missing at " + exe + ": reinstall or rebuild the Trojan app, then retry"
		}
	}
	add(doctorCheck{Check: "engine_binary", OK: engineOK, Detail: engineDetail})

	balance := -1
	if signedIn {
		if info, err := fetchLicense(cfg.AccessToken); err != nil {
			add(doctorCheck{Check: "token_balance", OK: true, Warning: true, Detail: "could not read the token balance (" + err.Error() + "); the test will still try"})
		} else {
			balance = info.TokenBalance
			ok := balance >= typicalTestTokens
			d := fmt.Sprintf("%d Trojan tokens available", balance)
			if !ok {
				d += fmt.Sprintf(", below the typical cost of one test (~%d). Top up at https://trojancli.com/pricing first, or the run will stop partway", typicalTestTokens)
			}
			add(doctorCheck{Check: "token_balance", OK: ok, Detail: d})
		}
	}

	target := normalizeSiteURL(req.GetString("url", ""))
	var estimate map[string]any
	if target != "" && target != "https://" {
		email := ""
		if cfg != nil {
			email = cfg.UserEmail
		}
		if allowed, isLocal, _, domain, err := dast.GateStatus(target, email); err != nil {
			add(doctorCheck{Check: "target_url", OK: false, Detail: err.Error()})
		} else if !allowed {
			add(doctorCheck{Check: "ownership", OK: true, Warning: true, Detail: fmt.Sprintf("Trojan hasn't been told the user owns %s. Ask them before starting; start_website_test then needs owner_confirmed=true", domain)})
		} else if isLocal {
			add(doctorCheck{Check: "ownership", OK: true, Detail: "local target, no ownership check needed"})
		} else {
			add(doctorCheck{Check: "ownership", OK: true, Detail: "ownership of " + domain + " already confirmed"})
		}
		add(checkReachable(ctx, target))

		siteDir, _ := normalizer.WebsiteDir(target)
		accounts := checkTestAccounts(ctx, siteDir)
		checks = append(checks, accounts...)

		estimate = map[string]any{
			"tokens":   fmt.Sprintf("about %d Trojan tokens (metered by actual use; larger sites cost more)", typicalTestTokens),
			"duration": typicalDuration,
		}
		if r := loadRun(siteDir); r != nil {
			prev := r.duration()
			if prev == 0 && r.PrevDurationSec > 0 {
				prev = time.Duration(r.PrevDurationSec) * time.Second
			}
			if prev > 0 {
				estimate["duration"] = fmt.Sprintf("about %s (this site's last test took that long)", formatDuration(prev))
			}
		}
		if balance >= 0 {
			estimate["balance_after"] = fmt.Sprintf("about %d tokens", balance-typicalTestTokens)
		}
	}

	ready := true
	for _, c := range checks {
		if !c.OK {
			ready = false
		}
	}
	note := "A website test is metered by the account's Trojan token balance, not a plan. If these checks pass but a test still fails with a 401, the sign-in has expired: sign in again."
	if target == "" || target == "https://" {
		note = "Pass url to also check the site is reachable, that its saved test accounts log in, and get a cost/time estimate. " + note
	}
	out := struct {
		Ready    bool           `json:"ready"`
		URL      string         `json:"url,omitempty"`
		Checks   []doctorCheck  `json:"checks"`
		Estimate map[string]any `json:"estimate,omitempty"`
		Note     string         `json:"note"`
	}{Ready: ready, Checks: checks, Estimate: estimate, Note: note}
	if target != "https://" {
		out.URL = target
	}
	data, _ := json.MarshalIndent(out, "", "  ")
	return mcp.NewToolResultText(string(data)), nil
}

// fetchLicense is swapped in tests (it calls Trojan's account service).
var fetchLicense = ai.FetchLicense

// checkReachable sends one GET to the target and reports how it answered.
func checkReachable(ctx context.Context, target string) doctorCheck {
	rctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	hreq, err := http.NewRequestWithContext(rctx, http.MethodGet, target, nil)
	if err != nil {
		return doctorCheck{Check: "reachable", OK: false, Detail: "invalid URL: " + err.Error()}
	}
	start := time.Now()
	resp, err := doctorHTTPClient.Do(hreq)
	if err != nil {
		return doctorCheck{Check: "reachable", OK: false, Detail: fmt.Sprintf("%s did not answer (%s). Start the site (or check the URL), then retry: a test against a dead site wastes tokens", target, err)}
	}
	resp.Body.Close()
	ms := time.Since(start).Milliseconds()
	if resp.StatusCode >= 500 {
		return doctorCheck{Check: "reachable", OK: true, Warning: true, Detail: fmt.Sprintf("%s answered HTTP %d in %dms: it is up but erroring, so results may be thin", target, resp.StatusCode, ms)}
	}
	return doctorCheck{Check: "reachable", OK: true, Detail: fmt.Sprintf("%s answered HTTP %d in %dms", target, resp.StatusCode, ms)}
}

// checkTestAccounts tries each saved test account's login once. The engine
// aborts a whole run when any saved login fails, so this is worth knowing up
// front. Passwords are never echoed.
func checkTestAccounts(ctx context.Context, siteDir string) []doctorCheck {
	data, err := os.ReadFile(filepath.Join(siteDir, "identities.json"))
	if err != nil {
		return []doctorCheck{{Check: "test_accounts", OK: true, Warning: true,
			Detail: "no saved test accounts for this site: the test runs logged-out only and can't find access-control bugs (IDOR, role escalation) behind the login. Add two test accounts in the Trojan app (Live URL Testing → Test accounts) to cover that"}}
	}
	var doc struct {
		Identities []agent.Identity `json:"identities"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return []doctorCheck{{Check: "test_accounts", OK: false, Detail: "the saved test accounts file is not valid JSON (" + err.Error() + "); the engine will refuse to start. Re-save the accounts in the Trojan app"}}
	}
	if len(doc.Identities) == 0 {
		return []doctorCheck{{Check: "test_accounts", OK: true, Warning: true, Detail: "the saved test accounts list is empty: the test runs logged-out only"}}
	}
	var out []doctorCheck
	for _, id := range doc.Identities {
		name := "test_account:" + id.Name
		switch {
		case len(id.Headers) > 0:
			out = append(out, doctorCheck{Check: name, OK: true, Warning: true, Detail: "uses a saved session header; Trojan can't check it without the site's logged-in page, and an expired session makes this account act logged-out"})
		case id.Login == nil:
			out = append(out, doctorCheck{Check: name, OK: false, Detail: "has neither a login nor a session header; remove or re-save it"})
		default:
			lc := agent.CheckLogin(ctx, doctorHTTPClient, id.Login)
			d := lc.Detail
			if !lc.OK {
				d += ". The engine stops the whole test when a saved login fails: fix this account in the Trojan app (Live URL Testing → Test accounts) first"
			}
			out = append(out, doctorCheck{Check: name, OK: lc.OK, Detail: d})
		}
	}
	if len(doc.Identities) == 1 {
		out = append(out, doctorCheck{Check: "test_accounts", OK: true, Warning: true, Detail: "only one test account: cross-account checks (can user A read user B's data?) need two"})
	}
	return out
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
	// If the dashboard saved test logins for this site, hand them to the engine
	// so it can authenticate and reach the logged-in attack surface (IDOR, etc.).
	// The file holds the credentials; the agent/model only ever sees the captured
	// session, never the password.
	idf := filepath.Join(siteDir, "identities.json")
	if _, e := os.Stat(idf); e == nil {
		args = append(args, "--identities-file", idf)
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
	projectPath := ""
	if p := expandHome(strings.TrimSpace(req.GetString("project_path", ""))); p != "" {
		if info, err := os.Stat(p); err == nil && info.IsDir() {
			projectPath = filepath.Clean(p)
			cmd.Dir = projectPath
			cmd.Args = append(cmd.Args, "--grey-box")
		}
	}
	prevDur := 0
	if prev := loadRun(siteDir); prev != nil {
		prevDur = int(prev.duration().Seconds())
		if prevDur == 0 {
			prevDur = prev.PrevDurationSec
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

	run := &websiteRun{URL: target, PID: cmd.Process.Pid, State: "running", StartedAt: time.Now().UTC(),
		ProjectPath: projectPath, PrevDurationSec: prevDur}
	saveRun(siteDir, run)
	done := make(chan struct{})
	activeRuns.Store(siteDir, done)
	go func() {
		err := cmd.Wait()
		logf.Close()
		now := time.Now().UTC()
		run.FinishedAt = &now
		run.ExitCode = cmd.ProcessState.ExitCode()
		run.State, run.Reason = finalizeRun(siteDir, err, run.ExitCode)
		saveRun(siteDir, run)
		activeRuns.Delete(siteDir)
		close(done)
	}()

	mode := "look only: Trojan reads pages and changes nothing"
	if thorough {
		mode = "try to get in: Trojan also submits forms and may leave test entries"
	}
	expect := typicalDuration
	if prevDur > 0 {
		expect = "about " + formatDuration(time.Duration(prevDur)*time.Second) + " (this site's last test)"
	}
	started := fmt.Sprintf("Started Trojan's AI penetration test of %s (%s). It uses the user's Trojan credits and should take %s.", target, mode, expect)
	if req.GetBool("wait", false) {
		return waitAndReport(ctx, req, siteDir, started)
	}
	return mcp.NewToolResultText(started + " Check progress with website_test_status (pass wait=true to block until it finishes), then read results with get_website_findings."), nil
}

// Wait bounds for blocking calls. A test usually takes 5-15 minutes; the cap
// keeps one tool call from hanging forever on a stuck engine.
const (
	defaultWaitMinutes = 20
	maxWaitMinutes     = 45
)

// waitPollInterval is how often a blocking wait re-reads the run (a var so
// tests can shorten it).
var waitPollInterval = 3 * time.Second

// waitBudget reads max_wait_minutes, clamped to [1, maxWaitMinutes].
func waitBudget(req mcp.CallToolRequest) time.Duration {
	m := req.GetInt("max_wait_minutes", defaultWaitMinutes)
	if m < 1 {
		m = 1
	}
	if m > maxWaitMinutes {
		m = maxWaitMinutes
	}
	return time.Duration(m) * time.Minute
}

// waitForRun blocks until the site's run leaves "running", maxWait passes, or
// ctx is cancelled (the client gave up: the test keeps going in the
// background). It calls tick on every poll so the caller can stream progress.
// timedOut is true when it returned while the run was still going.
func waitForRun(ctx context.Context, siteDir string, maxWait time.Duration, tick func(*websiteRun, runProgress)) (r *websiteRun, timedOut bool) {
	deadline := time.NewTimer(maxWait)
	defer deadline.Stop()
	poll := time.NewTicker(waitPollInterval)
	defer poll.Stop()
	for {
		r = loadRun(siteDir)
		if r == nil {
			return nil, false
		}
		if r.State != "running" {
			// The engine may have exited a moment before this process saved
			// its verdict; wait (briefly) for the real one.
			if ch, ok := activeRuns.Load(siteDir); ok {
				select {
				case <-ch.(chan struct{}):
				case <-time.After(10 * time.Second):
				}
				r = loadRun(siteDir)
			}
			return r, false
		}
		if tick != nil {
			p, _ := readRunProgress(siteDir)
			tick(r, p)
		}
		select {
		case <-ctx.Done():
			return r, true
		case <-deadline.C:
			return r, true
		case <-poll.C:
		}
	}
}

// progressNotifier streams MCP progress notifications for a blocking call when
// the client asked for them (a progressToken). Progress is elapsed seconds, so
// it always increases as the spec requires; the message carries phase and
// percent. Clients that reset their timeout on progress keep the call alive.
func progressNotifier(ctx context.Context, req mcp.CallToolRequest) func(*websiteRun, runProgress) {
	if req.Params.Meta == nil || req.Params.Meta.ProgressToken == nil {
		return nil
	}
	srv := server.ServerFromContext(ctx)
	if srv == nil {
		return nil
	}
	token := req.Params.Meta.ProgressToken
	last := -1
	return func(r *websiteRun, p runProgress) {
		elapsed := int(time.Since(r.StartedAt).Seconds())
		if elapsed <= last {
			return
		}
		last = elapsed
		msg := fmt.Sprintf("%s (~%d%%): %d agent steps, %d probes, %d finding(s) so far", p.PhaseLabel, p.PercentEstimate, p.AgentSteps, p.ProbesSent, len(p.FindingsSoFar))
		srv.SendNotificationToClient(ctx, "notifications/progress", map[string]any{ //nolint:errcheck
			"progressToken": token,
			"progress":      elapsed,
			"message":       msg,
		})
	}
}

// waitAndReport blocks on the site's run and returns the outcome: findings
// (with coverage) when it finished, the reason when it failed, and a
// keep-waiting hint with live progress when the wait budget ran out.
func waitAndReport(ctx context.Context, req mcp.CallToolRequest, siteDir, preamble string) (*mcp.CallToolResult, error) {
	r, timedOut := waitForRun(ctx, siteDir, waitBudget(req), progressNotifier(ctx, req))
	if r == nil {
		return mcp.NewToolResultError("lost track of the test run (its state file is missing). Check website_test_status."), nil
	}
	if timedOut {
		st := runStatusFor(siteDir, websiteProjectPath(req, siteDir), r)
		st.Message = strings.TrimSpace(preamble + fmt.Sprintf(" Still running after %s; the test continues in the background. Call website_test_status(url=%q, wait=true) to keep waiting, or poll without wait.",
			formatDuration(time.Since(r.StartedAt)), r.URL))
		return jsonResult(st)
	}
	if r.State != "finished" {
		return failedRunResult(siteDir, r), nil
	}
	payload, err := websiteFindingsPayload(siteDir, websiteProjectPath(req, siteDir))
	if err != nil {
		return mcp.NewToolResultError("the test finished but its results could not be read: " + err.Error()), nil
	}
	out := struct {
		State    string `json:"state"`
		Message  string `json:"message"`
		Duration string `json:"duration"`
		*websiteFindingsResult
	}{
		State:                 "finished",
		Message:               strings.TrimSpace(preamble + fmt.Sprintf(" Finished in %s with %d finding(s).", formatDuration(r.duration()), len(payload.Findings))),
		Duration:              formatDuration(r.duration()),
		websiteFindingsResult: payload,
	}
	return jsonResult(out)
}

// runStatus is website_test_status' structured answer.
type runStatus struct {
	State     string            `json:"state"` // running | finished | failed
	URL       string            `json:"url"`
	Message   string            `json:"message"`
	StartedAt time.Time         `json:"started_at"`
	Elapsed   string            `json:"elapsed"`
	Expected  string            `json:"expected_duration,omitempty"`
	Duration  string            `json:"duration,omitempty"`
	Progress  *runProgress      `json:"progress,omitempty"`
	Coverage  *coverageManifest `json:"coverage,omitempty"`
	Reason    string            `json:"reason,omitempty"`
	LastLines string            `json:"last_output,omitempty"`
}

// runStatusFor builds the structured status of a run from its record + log.
func runStatusFor(siteDir, projectPath string, r *websiteRun) runStatus {
	st := runStatus{State: r.State, URL: r.URL, StartedAt: r.StartedAt}
	end := time.Now()
	if r.FinishedAt != nil {
		end = *r.FinishedAt
		st.Duration = formatDuration(r.duration())
	}
	st.Elapsed = formatDuration(end.Sub(r.StartedAt))
	if r.PrevDurationSec > 0 {
		st.Expected = "about " + formatDuration(time.Duration(r.PrevDurationSec)*time.Second) + " (this site's last test)"
	} else {
		st.Expected = typicalDuration
	}
	if p, ok := readRunProgress(siteDir); ok {
		if r.State == "finished" {
			cov := p.coverage(projectPath)
			st.Coverage = &cov
		}
		st.Progress = &p
	}
	return st
}

// failedRunResult reports a failed run with its reason and the log's tail.
func failedRunResult(siteDir string, r *websiteRun) *mcp.CallToolResult {
	reason := r.Reason
	if reason == "" {
		reason = "the test stopped without finishing."
	}
	tail := ""
	if data, err := os.ReadFile(filepath.Join(siteDir, "last-run.log")); err == nil {
		lines := strings.Split(strings.TrimSpace(ansiRe.ReplaceAllString(string(data), "")), "\n")
		if len(lines) > 15 {
			lines = lines[len(lines)-15:]
		}
		tail = strings.Join(lines, "\n")
	}
	return mcp.NewToolResultError(fmt.Sprintf("The test of %s failed: %s\n\nLast output:\n%s", r.URL, reason, tail))
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

	if r.State == "running" && req.GetBool("wait", false) {
		return waitAndReport(ctx, req, siteDir, "")
	}
	switch r.State {
	case "running":
		st := runStatusFor(siteDir, websiteProjectPath(req, siteDir), r)
		st.Message = fmt.Sprintf("Still running: %s, %s in (expected %s).", r.URL, st.Elapsed, st.Expected)
		if st.Progress != nil {
			st.Message += fmt.Sprintf(" Phase: %s (~%d%%).", st.Progress.PhaseLabel, st.Progress.PercentEstimate)
		}
		st.Message += " Call again with wait=true to block until it finishes instead of polling."
		return jsonResult(st)
	case "finished":
		st := runStatusFor(siteDir, websiteProjectPath(req, siteDir), r)
		st.Message = fmt.Sprintf("Finished: %s in %s. Read the results with get_website_findings(url=%q); coverage below shows what the test reached.", r.URL, st.Duration, r.URL)
		return jsonResult(st)
	}
	return failedRunResult(siteDir, r), nil
}
