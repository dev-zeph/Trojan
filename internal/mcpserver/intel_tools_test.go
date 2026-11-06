package mcpserver

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mark3labs/mcp-go/mcp"

	"github.com/dev-zeph/trojan/internal/intel"
	"github.com/dev-zeph/trojan/internal/normalizer"
)

const nextAdvisory = `{"id":"GHSA-f82v-jwr5-mffw","source":"ghsa","kind":"vulnerability","ecosystem":"npm","package":"next",
 "affected_ranges":[{"type":"SEMVER","events":[{"introduced":"14.0.0"},{"fixed":"14.2.25"}]}],
 "severity":"critical","summary":"Authorization bypass in Next.js middleware","details":"Crafted x-middleware-subrequest header skips middleware.","playbook_id":"nextjs-middleware-bypass"}`
const semverAdvisory = `{"id":"GHSA-c2qf-rxjj-qqgw","source":"ghsa","kind":"vulnerability","ecosystem":"npm","package":"semver",
 "affected_ranges":[{"type":"SEMVER","events":[{"introduced":"7.0.0"},{"fixed":"7.5.2"}]}],
 "severity":"high","summary":"semver ReDoS","playbook_id":null}`
const eventStreamAdvisory = `{"id":"MAL-2018-1","source":"osv","kind":"malicious","ecosystem":"npm","package":"event-stream",
 "affected_versions":["3.3.6"],"severity":"critical","summary":"flatmap-stream backdoor"}`

type intelEnv struct {
	project string
	advs    *[]string
	status  *int
	body    *string
}

// newIntelEnv sets up a signed-in HOME, a temp copy of the fixture project and
// a fake intel server.
func newIntelEnv(t *testing.T, advs ...string) *intelEnv {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	project := t.TempDir()
	for _, f := range []string{"package.json", "package-lock.json"} {
		data, err := os.ReadFile(filepath.Join("testdata", "intelproj", f))
		if err != nil {
			t.Fatal(err)
		}
		os.WriteFile(filepath.Join(project, f), data, 0o644) //nolint:errcheck
	}
	status, body := 0, ""
	list := advs
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if status != 0 {
			w.WriteHeader(status)
			w.Write([]byte(body)) //nolint:errcheck
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"generated_at":"2026-11-05T00:00:00Z","advisories":[` + strings.Join(list, ",") + `]}`)) //nolint:errcheck
	}))
	t.Cleanup(srv.Close)
	old := newIntelClient
	newIntelClient = func() *intel.Client {
		return &intel.Client{URL: srv.URL, Token: func() (string, error) { return "tok", nil }}
	}
	t.Cleanup(func() { newIntelClient = old })
	return &intelEnv{project: project, advs: &list, status: &status, body: &body}
}

func (e *intelEnv) pf() projectFunc {
	return func(context.Context, mcp.CallToolRequest) (string, error) { return e.project, nil }
}

func (e *intelEnv) check(t *testing.T) (string, bool) {
	t.Helper()
	return callTool(t, handleCheckIntel(e.pf()), nil)
}

func (e *intelEnv) prove(t *testing.T, args map[string]any) (string, bool) {
	t.Helper()
	return callTool(t, handleProveIntelMatch(e.pf()), args)
}

func (e *intelEnv) upgradeNext(t *testing.T, to string) {
	t.Helper()
	p := filepath.Join(e.project, "package-lock.json")
	data, _ := os.ReadFile(p)
	os.WriteFile(p, []byte(strings.Replace(string(data), `"version": "14.1.0"`, `"version": "`+to+`"`, 1)), 0o644) //nolint:errcheck
}

const (
	nextID  = "GHSA-f82v-jwr5-mffw|npm|next@14.1.0"
	semID   = "GHSA-c2qf-rxjj-qqgw|npm|semver@7.5.1"
	eventID = "MAL-2018-1|npm|event-stream@3.3.6"
)

func TestCheckIntelProposesNeverAsserts(t *testing.T) {
	e := newIntelEnv(t, nextAdvisory, eventStreamAdvisory)
	out, isErr := e.check(t)
	if isErr {
		t.Fatal(out)
	}
	for _, want := range []string{
		"next 14.1.0 matches a recent advisory (GHSA-f82v-jwr5-mffw, critical): Authorization bypass in Next.js middleware",
		"Status: matched, unproven. Want me to check whether your app is actually affected, and fix it? Fix: upgrade to 14.2.25.",
		"a release of event-stream you have installed (3.3.6) was published by an attacker",
		"package-lock.json", "Intel freshness", "get_dependency_risks lists static CVEs",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
	low := strings.ToLower(out)
	if strings.Contains(low, "you are vulnerable") || strings.Contains(low, "your app is vulnerable") || strings.Contains(low, "you are safe") {
		t.Errorf("output asserts a verdict:\n%s", out)
	}
	if strings.Contains(out, "\u2014") {
		t.Error("em dash in user-facing text")
	}
	ign, _ := os.ReadFile(filepath.Join(e.project, ".gitignore"))
	_ = ign // gitignore is only written inside a git repo; matches.json existence is the check below
	if _, err := os.Stat(filepath.Join(e.project, ".trojan", "intel", "matches.json")); err != nil {
		t.Errorf("matches.json not written: %v", err)
	}
}

func TestCheckIntelErrors(t *testing.T) {
	e := newIntelEnv(t, nextAdvisory)
	*e.status, *e.body = 402, `{"error":"subscription_required","message":"Your plan does not include dependency intel."}`
	out, isErr := e.check(t)
	if !isErr || !strings.Contains(out, "Your plan does not include dependency intel.") || strings.Contains(out, "Pro/Team") {
		t.Errorf("402 output: %v %q", isErr, out)
	}

	newIntelClient = func() *intel.Client {
		return &intel.Client{URL: "http://127.0.0.1:1", Token: func() (string, error) { return "", intel.ErrNotSignedIn }}
	}
	out, isErr = e.check(t)
	if !isErr || !strings.Contains(out, "trojan login") {
		t.Errorf("not signed in output: %v %q", isErr, out)
	}
}

func TestCheckIntelNoMatches(t *testing.T) {
	e := newIntelEnv(t)
	out, _ := e.check(t)
	if !strings.Contains(out, "No installed package matches an advisory") || !strings.Contains(out, "2026-11-05") {
		t.Errorf("no-match output: %s", out)
	}
	if strings.Contains(strings.ToLower(out), "you are safe") || strings.Contains(out, "it is not a statement that the project is safe") == false {
		t.Errorf("no-match wording: %s", out)
	}
}

func TestMatchHistoryPersistsAndResolves(t *testing.T) {
	e := newIntelEnv(t, nextAdvisory, semverAdvisory)
	e.check(t)
	// Promote semver (no playbook) so there is a status to preserve.
	if out, isErr := e.prove(t, map[string]any{"match_id": semID}); isErr || !strings.Contains(out, "CONFIRMED") {
		t.Fatalf("%v %s", isErr, out)
	}
	e.check(t)
	st := loadIntelStore(e.project)
	if r := st.find(semID); r == nil || r.Status != intelConfirmed {
		t.Fatalf("confirmed status not preserved: %+v", r)
	}
	if r := st.find(nextID); r == nil || r.Status != intelMatched || r.FirstSeen.IsZero() {
		t.Fatalf("next record: %+v", r)
	}
	// Upgrade next out of range: its match vanishes and is marked resolved.
	e.upgradeNext(t, "14.2.25")
	e.check(t)
	st = loadIntelStore(e.project)
	if r := st.find(nextID); r.Status != intelResolved || r.ResolvedAt == nil {
		t.Fatalf("vanished match not resolved: %+v", r)
	}
	if r := st.find(semID); r.Status != intelConfirmed {
		t.Fatalf("semver lost its status: %+v", r)
	}
}

func TestProveVersionCheckConfirmsThenFixed(t *testing.T) {
	e := newIntelEnv(t, semverAdvisory)
	e.check(t)
	out, isErr := e.prove(t, map[string]any{"match_id": semID})
	if isErr {
		t.Fatal(out)
	}
	for _, want := range []string{"CONFIRMED (version only)", "in the affected range; whether your code is affected was not tested", "npm install semver@7.5.2"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in %s", want, out)
		}
	}
	// A playbook draft is written for the advisory without one.
	draft := filepath.Join(e.project, ".trojan", "intel", "playbook-drafts", "GHSA-c2qf-rxjj-qqgw.json")
	data, err := os.ReadFile(draft)
	if err != nil {
		t.Fatalf("no playbook draft: %v", err)
	}
	var d map[string]any
	json.Unmarshal(data, &d) //nolint:errcheck
	if d["status"] != "draft" || d["needs_author_review"] != true || d["breach_story"] == "" || d["prompt_body"] == "" {
		t.Errorf("draft shape: %s", data)
	}
	if !strings.Contains(out, "draft was saved for review") {
		t.Errorf("output does not mention the draft: %s", out)
	}

	// Promoted finding is visible to get_findings, and carries the fix.
	findings, _ := callTool(t, handleGetFindings(e.pf()), nil)
	if !strings.Contains(findings, intelFindingID(semID)) {
		t.Fatalf("promoted finding not in get_findings: %s", findings)
	}
	scan, err := loadLatestScan(e.project)
	if err != nil {
		t.Fatal(err)
	}
	var f *normalizer.Finding
	for i := range scan.Findings {
		if scan.Findings[i].ID == intelFindingID(semID) {
			f = &scan.Findings[i]
		}
	}
	if f == nil || f.Scanner != "trojan-intel" || f.Category != "sca" || f.FilePath != "package-lock.json" || f.Severity != normalizer.SeverityHigh {
		t.Fatalf("finding: %+v", f)
	}
	fixable, _ := callTool(t, handleGetFixableFindings(e.pf()), nil)
	if !strings.Contains(fixable, intelFindingID(semID)) {
		t.Errorf("not in get_fixable_findings: %s", fixable)
	}

	// verify_fix before the upgrade: not fixed. After: fixed.
	vf := handleVerifyFix(e.pf())
	if out, _ := callTool(t, vf, map[string]any{"id": f.ID}); !strings.Contains(out, "NOT FIXED") {
		t.Errorf("verify before upgrade: %s", out)
	}
	p := filepath.Join(e.project, "package-lock.json")
	lock, _ := os.ReadFile(p)
	os.WriteFile(p, []byte(strings.Replace(string(lock), `"node_modules/semver": { "version": "7.5.1" }`, `"node_modules/semver": { "version": "7.5.4" }`, 1)), 0o644) //nolint:errcheck
	if out, isErr := callTool(t, vf, map[string]any{"id": f.ID}); isErr || !strings.Contains(out, "VERIFIED FIXED") {
		t.Errorf("verify after upgrade: %v %s", isErr, out)
	}
	scan, _ = loadLatestScan(e.project)
	for _, sf := range scan.Findings {
		if sf.ID == f.ID && sf.Status != normalizer.StatusResolved {
			t.Errorf("finding not resolved: %+v", sf)
		}
	}
	if r := loadIntelStore(e.project).find(semID); r.Status != intelFixed {
		t.Errorf("record status = %s", r.Status)
	}
}

func TestProveFixedAfterUpgrade(t *testing.T) {
	e := newIntelEnv(t, nextAdvisory)
	e.check(t)
	e.upgradeNext(t, "14.2.25")
	out, isErr := e.prove(t, map[string]any{"match_id": nextID})
	if isErr || !strings.Contains(out, "FIXED") || !strings.Contains(out, "outside the affected range") {
		t.Errorf("%v %s", isErr, out)
	}
	if r := loadIntelStore(e.project).find(nextID); r.Status != intelFixed {
		t.Errorf("status = %s", r.Status)
	}
}

func TestProveMaliciousConfirmed(t *testing.T) {
	e := newIntelEnv(t, eventStreamAdvisory)
	e.check(t)
	out, isErr := e.prove(t, map[string]any{"match_id": eventID})
	if isErr || !strings.Contains(out, "CONFIRMED") || !strings.Contains(out, "published by an attacker") || !strings.Contains(out, "rotate") {
		t.Errorf("%v %s", isErr, out)
	}
	if _, err := os.Stat(filepath.Join(e.project, ".trojan", "intel", "playbook-drafts")); err == nil {
		t.Error("a malicious release must not produce a playbook draft")
	}
}

func TestProveUnknownMatch(t *testing.T) {
	e := newIntelEnv(t, nextAdvisory)
	out, isErr := e.prove(t, map[string]any{"match_id": "nope"})
	if !isErr || !strings.Contains(out, "Run check_intel first") {
		t.Errorf("%v %s", isErr, out)
	}
}

func TestProveHostedNeedsConfirmationThenStarts(t *testing.T) {
	e := newIntelEnv(t, nextAdvisory)
	e.check(t)
	var started []map[string]any
	old := startHostedTest
	startHostedTest = func(_ context.Context, args map[string]any) (*mcp.CallToolResult, error) {
		started = append(started, args)
		dir, _ := normalizer.WebsiteDir(normalizeSiteURL(args["url"].(string)))
		os.MkdirAll(dir, 0o700) //nolint:errcheck
		saveRun(dir, &websiteRun{URL: "http://localhost:3000", PID: os.Getpid(), State: "running", StartedAt: time.Now().UTC().Truncate(time.Second)})
		return mcp.NewToolResultText("Started Trojan's AI penetration test"), nil
	}
	t.Cleanup(func() { startHostedTest = old })

	args := map[string]any{"match_id": nextID, "target_url": "http://localhost:3000"}
	out, isErr := e.prove(t, args)
	if isErr || len(started) != 0 {
		t.Fatalf("started without confirmation: %v %v", isErr, started)
	}
	for _, want := range []string{"Confirmation needed", "spends the user's Trojan credits", "owner_confirmed=true", "Nothing has been started"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in %s", want, out)
		}
	}
	if r := loadIntelStore(e.project).find(nextID); r.Status != intelMatched {
		t.Errorf("status changed without confirmation: %s", r.Status)
	}

	args["owner_confirmed"] = true
	out, isErr = e.prove(t, args)
	if isErr || len(started) != 1 {
		t.Fatalf("%v %v %s", isErr, started, out)
	}
	if started[0]["owner_confirmed"] != true || started[0]["project_path"] != e.project {
		t.Errorf("starter args: %v", started[0])
	}
	var tpl map[string]any
	json.Unmarshal([]byte(started[0]["attack_template"].(string)), &tpl) //nolint:errcheck
	if !strings.Contains(tpl["body"].(string), "nextjs-middleware-bypass") || !strings.Contains(tpl["body"].(string), "GHSA-f82v-jwr5-mffw") {
		t.Errorf("template: %v", tpl)
	}
	r := loadIntelStore(e.project).find(nextID)
	if r.Status != intelProving || r.TestID == "" || !strings.Contains(out, r.TestID) || !strings.Contains(out, "website_test_status") {
		t.Fatalf("record %+v out %s", r, out)
	}

	// Still running.
	out, _ = e.prove(t, map[string]any{"match_id": nextID})
	if !strings.Contains(out, "still running") {
		t.Errorf("%s", out)
	}

	// Finished with a matching finding: confirmed via hosted_test, promoted.
	finish := func(findings []normalizer.Finding) {
		dir, _ := normalizer.WebsiteDir("http://localhost:3000")
		run := loadRun(dir)
		fin := time.Now().UTC()
		run.State, run.FinishedAt = "finished", &fin
		saveRun(dir, run)
		normalizer.SaveWebsiteTest("http://localhost:3000", findings) //nolint:errcheck
	}
	finish([]normalizer.Finding{{ID: "w1", Title: "Middleware bypass (GHSA-f82v-jwr5-mffw)", Status: normalizer.StatusOpen}})
	out, isErr = e.prove(t, map[string]any{"match_id": nextID})
	if isErr || !strings.Contains(out, "CONFIRMED by Trojan's hosted test") {
		t.Fatalf("%v %s", isErr, out)
	}
	r = loadIntelStore(e.project).find(nextID)
	if r.Status != intelConfirmed || r.ProofKind != "hosted_test" || r.FindingID == "" {
		t.Errorf("record %+v", r)
	}
	scan, _ := loadLatestScan(e.project)
	if len(scan.Findings) != 1 || scan.Findings[0].ID != r.FindingID {
		t.Errorf("promoted finding missing: %+v", scan.Findings)
	}
}

func TestProveHostedNotReproduced(t *testing.T) {
	e := newIntelEnv(t, nextAdvisory)
	e.check(t)
	old := startHostedTest
	startHostedTest = func(_ context.Context, args map[string]any) (*mcp.CallToolResult, error) {
		dir, _ := normalizer.WebsiteDir(normalizeSiteURL(args["url"].(string)))
		os.MkdirAll(dir, 0o700) //nolint:errcheck
		fin := time.Now().UTC()
		saveRun(dir, &websiteRun{URL: "http://localhost:3000", State: "finished", StartedAt: fin.Add(-time.Minute), FinishedAt: &fin})
		normalizer.SaveWebsiteTest("http://localhost:3000", []normalizer.Finding{{ID: "w9", Title: "Missing CSP", Status: normalizer.StatusOpen}}) //nolint:errcheck
		return mcp.NewToolResultText("started"), nil
	}
	t.Cleanup(func() { startHostedTest = old })
	e.prove(t, map[string]any{"match_id": nextID, "target_url": "http://localhost:3000", "owner_confirmed": true})
	out, _ := e.prove(t, map[string]any{"match_id": nextID})
	if !strings.Contains(out, "NOT REPRODUCED") {
		t.Fatalf("%s", out)
	}
	if r := loadIntelStore(e.project).find(nextID); r.Status != intelNotAffected {
		t.Errorf("status = %s", r.Status)
	}
}

func TestProveWithPlaybookButNoTargetStaysUnproven(t *testing.T) {
	e := newIntelEnv(t, nextAdvisory)
	e.check(t)
	out, _ := e.prove(t, map[string]any{"match_id": nextID})
	if !strings.Contains(out, "Status stays matched, unproven") || !strings.Contains(out, "target_url") || !strings.Contains(out, "npm install next@14.2.25") {
		t.Errorf("%s", out)
	}
	if r := loadIntelStore(e.project).find(nextID); r.Status != intelMatched {
		t.Errorf("status = %s", r.Status)
	}
}

func TestUpgradeCommands(t *testing.T) {
	cases := map[string]string{
		"package-lock.json": "npm install p@2.0.0", "pnpm-lock.yaml": "pnpm add p@2.0.0", "yarn.lock": "yarn add p@2.0.0",
		"bun.lock": "bun add p@2.0.0", "poetry.lock": `poetry add "p>=2.0.0"`, "uv.lock": `uv add "p>=2.0.0"`,
		"services/api/requirements.txt": `pip install "p>=2.0.0"`,
	}
	for lock, want := range cases {
		got := upgradeCommand(intel.Match{Package: "p", FixedVersion: "2.0.0", Lockfile: lock})
		if !strings.HasPrefix(got, want) {
			t.Errorf("%s: got %q want %q", lock, got, want)
		}
	}
}
