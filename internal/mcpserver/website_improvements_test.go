package mcpserver

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dev-zeph/trojan/internal/ai"
	"github.com/dev-zeph/trojan/internal/normalizer"
)

// A trimmed copy of a real engine log (black-box run with two identities).
const sampleRunLog = "\x1b[1m  → Starting Trojan agentic pen-test\x1b[0m\n" +
	"  → Crawling application (depth 2)...\n" +
	"  → Discovered 3 endpoint(s)\n\n" +
	"  → Running Nuclei baseline...\n" +
	"[INF] Scan completed in 6m. 0 matches found.\n" +
	"  → Baseline: 0 finding(s)\n\n" +
	"  → 2 identities loaded for authorization testing: account-1, account-2\n\n" +
	"  → White-box review: forming hypotheses from the source...\n" +
	"  Grey-box requested but no recognizable source found in the current directory — running black-box.\n\n" +
	"  [step 1]\n" +
	"    → get_crawl_map\n" +
	"  [step 2]\n" +
	"    → http_probe\n" +
	"      200 http://127.0.0.1:3400/admin\n" +
	"    → http_probe\n" +
	"      302 http://127.0.0.1:3400/login?next=%2F\n" +
	"    → diff_responses\n" +
	"      #8 (200) vs #9 (200) → possible_bola, 100% similar\n" +
	"  [step 3]\n" +
	"    → http_probe\n" +
	"      405 http://127.0.0.1:3400/admin\n" +
	"    ✓ finding: Broken access control on /admin\n"

func TestParseRunLog_InProgress(t *testing.T) {
	p := parseRunLog(sampleRunLog)
	if p.Phase != phaseTesting || p.AgentSteps != 3 || p.ProbesSent != 3 || p.ToolCalls != 5 {
		t.Errorf("counts: %+v", p)
	}
	if p.EndpointsDiscovered != 3 || len(p.Identities) != 2 || p.Identities[1] != "account-2" {
		t.Errorf("discovery/identities: %+v", p)
	}
	if p.Mode != "black-box" || p.ModeNote == "" {
		t.Errorf("mode: %q %q", p.Mode, p.ModeNote)
	}
	if len(p.FindingsSoFar) != 1 || p.FindingsSoFar[0] != "Broken access control on /admin" {
		t.Errorf("findings: %v", p.FindingsSoFar)
	}
	if st := p.reached["/admin"]; len(st) != 2 {
		t.Errorf("reached /admin = %v", st)
	}
	if _, ok := p.reached["/login"]; !ok {
		t.Errorf("query string not stripped: %v", p.reached)
	}
	if p.PercentEstimate <= 40 || p.PercentEstimate >= 92 {
		t.Errorf("percent = %d, want within the testing band", p.PercentEstimate)
	}
}

func TestParseRunLog_PhasesAndDone(t *testing.T) {
	if p := parseRunLog("  → Crawling application (depth 2)...\n"); p.Phase != phaseCrawling || p.PercentEstimate != 5 {
		t.Errorf("crawl: %+v", p)
	}
	if p := parseRunLog("  → Running Nuclei baseline...\n"); p.Phase != phaseBaseline {
		t.Errorf("baseline: %+v", p)
	}
	done := sampleRunLog + "  finished: Covered all endpoints\n  → Synthesizing 1 finding(s)...\nResults saved to /x\nPENTEST_END {\"outcome\":\"finished\"}\n"
	p := parseRunLog(done)
	if p.Phase != phaseDone || p.PercentEstimate != 100 || p.AgentSummary != "Covered all endpoints" {
		t.Errorf("done: %+v", p)
	}
}

const flaskApp = `from flask import Flask
app = Flask(__name__)

@app.route("/login", methods=["GET", "POST"])
def login():
    q = "SELECT * FROM users WHERE email = '%s'" % request.form["email"]
    conn.execute(q)
    return render_template("login.html")


@app.route("/admin")
@login_required
def admin():
    return render_template("admin.html")


@app.route("/tools/ping")
@login_required
def ping():
    return os.popen("ping " + request.args["host"]).read()
`

// mkFlaskProject writes a small Flask app plus a code scan whose findings use
// both absolute and relative paths, as real scanners do.
func mkFlaskProject(t *testing.T) string {
	t.Helper()
	proj := t.TempDir()
	write := func(rel, content string) {
		p := filepath.Join(proj, rel)
		os.MkdirAll(filepath.Dir(p), 0o755) //nolint:errcheck
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("requirements.txt", "flask\n")
	write("app.py", flaskApp)
	write("templates/login.html", "<form method=post><input type=password></form>")
	scan := normalizer.ScanResult{Timestamp: time.Now(), ProjectPath: proj, Findings: []normalizer.Finding{
		{ID: "semgrep-1", Severity: "high", Title: "SQL injection", FilePath: filepath.Join(proj, "app.py"), LineNumber: 6, Status: normalizer.StatusOpen},
		{ID: "semgrep-2", Severity: "high", Title: "Command injection", FilePath: "app.py", LineNumber: 20, Status: normalizer.StatusOpen},
		{ID: "semgrep-3", Severity: "medium", Title: "Missing CSRF token", FilePath: filepath.Join(proj, "templates/login.html"), LineNumber: 1, Status: normalizer.StatusOpen},
	}}
	data, _ := json.Marshal(scan)
	write(".trojan/scans/2026-11-04T10-00-00.json", string(data))
	return proj
}

func TestGetWebsiteFindings_CorrelatesWithCode(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	proj := mkFlaskProject(t)
	normalizer.SaveWebsiteTest("http://127.0.0.1:3400", []normalizer.Finding{ //nolint:errcheck
		{ID: "agentic-sqli", Category: "dast", Title: "SQLi in /login", FilePath: "http://127.0.0.1:3400/login", Status: normalizer.StatusOpen},
		{ID: "agentic-admin", Category: "dast", Title: "Broken access control on /admin", FilePath: "http://127.0.0.1:3400/admin", URL: "http://127.0.0.1:3400/admin", Status: normalizer.StatusOpen},
		{ID: "agentic-evil", Category: "dast", Title: "Agent named a file outside the project", URL: "http://127.0.0.1:3400/nope", SourceFile: "../../etc/passwd", SourceLine: 1},
	})

	text, isErr := callTool(t, handleGetWebsiteFindings, map[string]any{"url": "http://127.0.0.1:3400", "project_path": proj})
	if isErr {
		t.Fatal(text)
	}
	var got websiteFindingsResult
	if err := json.Unmarshal([]byte(text), &got); err != nil {
		t.Fatalf("%v: %s", err, text)
	}
	byID := map[string]websiteFinding{}
	for _, f := range got.Findings {
		byID[f.ID] = f
	}

	sqli := byID["agentic-sqli"]
	if sqli.Location != "app.py:4" || sqli.Language == "" || sqli.Framework != "flask" || !strings.Contains(sqli.SurroundingCode, "SELECT") {
		t.Errorf("sqli placement: loc=%q lang=%q fw=%q code=%q", sqli.Location, sqli.Language, sqli.Framework, sqli.SurroundingCode)
	}
	rel := map[string]string{}
	for _, r := range sqli.RelatedFindings {
		rel[r.ID] = r.Relation
	}
	if rel["semgrep-1"] != "same_handler" || rel["semgrep-3"] != "rendered_template" {
		t.Errorf("sqli related = %+v", sqli.RelatedFindings)
	}
	if _, ok := rel["semgrep-2"]; ok {
		t.Errorf("a finding in another handler was linked: %+v", sqli.RelatedFindings)
	}

	admin := byID["agentic-admin"]
	if admin.Location != "app.py:11" || len(admin.RelatedFindings) != 0 || !strings.Contains(admin.CodeScanNote, "Only the live test") {
		t.Errorf("admin: loc=%q related=%v note=%q", admin.Location, admin.RelatedFindings, admin.CodeScanNote)
	}
	if evil := byID["agentic-evil"]; evil.SourceFile != "" || evil.Location != "" {
		t.Errorf("out-of-project source file kept: %+v", evil)
	}

	if len(got.NextSteps) == 0 || !strings.Contains(got.NextSteps[0], "retest_website_findings") || !strings.Contains(got.NextSteps[0], `"agentic-sqli"`) {
		t.Errorf("next_steps should point at retest: %v", got.NextSteps)
	}
}

func TestGetWebsiteFindings_NoProjectSuggestsIt(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	normalizer.SaveWebsiteTest("http://127.0.0.1:3400", []normalizer.Finding{{ID: "a", Category: "dast", FilePath: "http://127.0.0.1:3400/admin", Status: normalizer.StatusOpen}}) //nolint:errcheck
	text, _ := callTool(t, handleGetWebsiteFindings, map[string]any{"url": "http://127.0.0.1:3400"})
	if !strings.Contains(text, "Pass project_path") || strings.Contains(text, "related_findings\":") {
		t.Errorf("expected a project_path hint and no links: %s", text)
	}
}

func TestCoverage_ListsUnreachedRoutes(t *testing.T) {
	proj := mkFlaskProject(t)
	cov := parseRunLog(sampleRunLog).coverage(proj)
	var missed []string
	for _, r := range cov.RoutesNotReached {
		missed = append(missed, r.Route)
	}
	if strings.Join(missed, ",") != "GET /tools/ping" {
		t.Errorf("routes_not_reached = %v (reached %v)", missed, cov.PathsReached)
	}
	if cov.SourceRoutes != 4 || len(cov.PathsReached) != 2 {
		t.Errorf("coverage = %+v", cov)
	}
	if noProj := parseRunLog(sampleRunLog).coverage(""); noProj.RoutesNotReached != nil || !strings.Contains(noProj.Note, "project_path") {
		t.Errorf("no-project coverage = %+v", noProj)
	}
}

// writeRun puts a run record + log in the site's folder.
func writeRun(t *testing.T, target string, r *websiteRun, log string) string {
	t.Helper()
	dir, err := normalizer.WebsiteDir(target)
	if err != nil {
		t.Fatal(err)
	}
	os.MkdirAll(dir, 0o700) //nolint:errcheck
	saveRun(dir, r)
	os.WriteFile(filepath.Join(dir, "last-run.log"), []byte(log), 0o600) //nolint:errcheck
	return dir
}

func TestWebsiteTestStatus_RunningReportsProgress(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	writeRun(t, "http://127.0.0.1:3400", &websiteRun{URL: "http://127.0.0.1:3400", PID: os.Getpid(), State: "running",
		StartedAt: time.Now().Add(-2 * time.Minute), PrevDurationSec: 600}, sampleRunLog)

	text, isErr := callTool(t, handleWebsiteTestStatus, map[string]any{"url": "http://127.0.0.1:3400"})
	if isErr {
		t.Fatal(text)
	}
	var st runStatus
	if err := json.Unmarshal([]byte(text), &st); err != nil {
		t.Fatalf("%v: %s", err, text)
	}
	if st.State != "running" || st.Progress == nil || st.Progress.Phase != phaseTesting || st.Progress.ProbesSent != 3 {
		t.Errorf("status = %s", text)
	}
	if !strings.Contains(st.Expected, "10m") || !strings.Contains(st.Message, "wait=true") {
		t.Errorf("expected/message: %q / %q", st.Expected, st.Message)
	}
}

func TestWebsiteTestStatus_WaitReturnsFindings(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	old := waitPollInterval
	waitPollInterval = 20 * time.Millisecond
	defer func() { waitPollInterval = old }()

	target := "http://127.0.0.1:3400"
	run := &websiteRun{URL: target, PID: os.Getpid(), State: "running", StartedAt: time.Now().UTC()}
	dir := writeRun(t, target, run, sampleRunLog)
	go func() {
		time.Sleep(100 * time.Millisecond)
		normalizer.SaveWebsiteTest(target, []normalizer.Finding{{ID: "agentic-1", Category: "dast", Title: "IDOR", FilePath: target + "/admin", Status: normalizer.StatusOpen}}) //nolint:errcheck
		now := time.Now().UTC()
		run.State, run.FinishedAt = "finished", &now
		saveRun(dir, run)
	}()

	text, isErr := callTool(t, handleWebsiteTestStatus, map[string]any{"url": target, "wait": true, "max_wait_minutes": 1})
	if isErr {
		t.Fatal(text)
	}
	var got struct {
		State    string
		Findings []websiteFinding
		Coverage *coverageManifest
	}
	if err := json.Unmarshal([]byte(text), &got); err != nil {
		t.Fatalf("%v: %s", err, text)
	}
	if got.State != "finished" || len(got.Findings) != 1 || got.Findings[0].ID != "agentic-1" || got.Coverage == nil {
		t.Errorf("wait result = %s", text)
	}
}

func TestWaitForRun_TimesOut(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	old := waitPollInterval
	waitPollInterval = 10 * time.Millisecond
	defer func() { waitPollInterval = old }()
	dir := writeRun(t, "http://127.0.0.1:3400", &websiteRun{URL: "http://127.0.0.1:3400", PID: os.Getpid(), State: "running", StartedAt: time.Now()}, sampleRunLog)
	ticks := 0
	r, timedOut := waitForRun(t.Context(), dir, 60*time.Millisecond, func(*websiteRun, runProgress) { ticks++ })
	if !timedOut || r == nil || r.State != "running" || ticks == 0 {
		t.Errorf("timedOut=%v r=%+v ticks=%d", timedOut, r, ticks)
	}
}

func TestWebsiteTestDoctor_URLChecks(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	oldFetch := fetchLicense
	fetchLicense = func(string) (*ai.LicenseInfo, error) { return nil, errors.New("offline") }
	defer func() { fetchLicense = oldFetch }()

	// A tiny site: right password redirects to /dashboard with a cookie; wrong
	// password re-renders the form AND sets a cookie (as flash messages do).
	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/login" && r.Method == http.MethodPost {
			r.ParseForm() //nolint:errcheck
			http.SetCookie(w, &http.Cookie{Name: "session", Value: "x", Path: "/"})
			if r.FormValue("password") == "right" {
				http.Redirect(w, r, "/dashboard", http.StatusFound)
				return
			}
			w.Write([]byte(`<form><input type="password" name="password"></form>`)) //nolint:errcheck
			return
		}
		w.Write([]byte("ok")) //nolint:errcheck
	}))
	defer site.Close()

	dir, _ := normalizer.WebsiteDir(site.URL)
	os.MkdirAll(dir, 0o700) //nolint:errcheck
	ids := `{"identities":[
	  {"name":"good","login":{"url":"` + site.URL + `/login","fields":{"email":"a@x","password":"right"}}},
	  {"name":"bad","login":{"url":"` + site.URL + `/login","fields":{"email":"b@x","password":"wrong"}}}]}`
	os.WriteFile(filepath.Join(dir, "identities.json"), []byte(ids), 0o600) //nolint:errcheck

	text, _ := callTool(t, handleWebsiteTestDoctor, map[string]any{"url": site.URL})
	var got struct {
		Ready    bool
		Checks   []doctorCheck
		Estimate map[string]any
	}
	if err := json.Unmarshal([]byte(text), &got); err != nil {
		t.Fatalf("%v: %s", err, text)
	}
	byName := map[string]doctorCheck{}
	for _, c := range got.Checks {
		byName[c.Check] = c
	}
	if got.Ready {
		t.Error("ready must be false with a failing login (and no sign-in)")
	}
	if !byName["reachable"].OK || !byName["test_account:good"].OK || byName["test_account:bad"].OK {
		t.Errorf("checks = %s", text)
	}
	if strings.Contains(text, "right") || strings.Contains(text, "wrong") {
		t.Error("doctor output leaked a password")
	}
	if got.Estimate["tokens"] == nil || got.Estimate["duration"] == nil {
		t.Errorf("estimate = %v", got.Estimate)
	}
}

func TestWebsiteTestDoctor_UnreachableTarget(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	site := httptest.NewServer(http.NotFoundHandler())
	url := site.URL
	site.Close() // nothing listens there now
	text, _ := callTool(t, handleWebsiteTestDoctor, map[string]any{"url": url})
	if !strings.Contains(text, `"check": "reachable"`) || !strings.Contains(text, "did not answer") || strings.Contains(text, `"ready": true`) {
		t.Errorf("doctor = %s", text)
	}
}

func TestCoverage_AliasOfReachedHandlerCountsAsReached(t *testing.T) {
	proj := t.TempDir()
	os.WriteFile(filepath.Join(proj, "index.php"), []byte("<?php echo 1;"), 0o644) //nolint:errcheck
	os.WriteFile(filepath.Join(proj, "admin.php"), []byte("<?php echo 2;"), 0o644) //nolint:errcheck
	log := "  [step 1]\n    → http_probe\n      200 http://127.0.0.1:3300/index.php\n"
	cov := parseRunLog(log).coverage(proj)
	if len(cov.RoutesNotReached) != 1 || cov.RoutesNotReached[0].Route != "ANY /admin.php" {
		t.Errorf("routes_not_reached = %+v", cov.RoutesNotReached)
	}
}
