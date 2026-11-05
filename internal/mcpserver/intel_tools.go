package mcpserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"

	"github.com/dev-zeph/trojan/internal/intel"
	"github.com/dev-zeph/trojan/internal/normalizer"
)

// check_intel and prove_intel_match: Trojan's breach-aware dependency intel.
//
// Intel PROPOSES. A match says "an installed version is inside an advisory's
// affected range"; it never says the app is exploitable. prove_intel_match
// moves a match along: a free version check first, then (only with a
// playbook, a target URL and the owner's explicit yes) a hosted test run by
// Trojan's own service. No testing logic lives here.

// newIntelClient builds the intel client (a var so tests can point it at a
// fake server).
var newIntelClient = func() *intel.Client { return intel.NewClient() }

// startHostedTest starts an owner-authorized website test. It is the SAME
// code path start_website_test uses; a var so tests can fake the spend.
var startHostedTest = func(ctx context.Context, args map[string]any) (*mcp.CallToolResult, error) {
	req := mcp.CallToolRequest{}
	req.Params.Arguments = args
	return handleStartWebsiteTest(ctx, req)
}

const intelContrast = "get_dependency_risks lists static CVEs from a Trivy scan; check_intel matches your exact installed versions against Trojan's curated, breach-aware intel and can verify and fix what it finds."

type matchView struct {
	ID             string `json:"id"`
	Package        string `json:"package"`
	Installed      string `json:"installed_version"`
	Ecosystem      string `json:"ecosystem"`
	Lockfile       string `json:"lockfile"`
	Advisory       string `json:"advisory"`
	Kind           string `json:"kind"`
	Severity       string `json:"severity"`
	Summary        string `json:"summary"`
	FixedVersion   string `json:"fixed_version,omitempty"`
	Direct         bool   `json:"direct"`
	ProofAvailable bool   `json:"proof_available"`
	Status         string `json:"status"`
}

func viewOf(r intelRecord) matchView {
	m := r.Match
	return matchView{ID: m.ID, Package: m.Package, Installed: m.InstalledVersion, Ecosystem: m.Ecosystem,
		Lockfile: m.Lockfile, Advisory: m.Advisory.ID, Kind: m.Kind, Severity: m.Severity, Summary: m.Advisory.Summary,
		FixedVersion: m.FixedVersion, Direct: m.Direct, ProofAvailable: m.ProofAvailable, Status: r.Status}
}

func intelErrorText(err error) string {
	var sub *intel.SubscriptionRequiredError
	switch {
	case errors.Is(err, intel.ErrNotSignedIn):
		return "Not signed in to Trojan, so intel can't be fetched. Run `trojan login` (or sign in via the Trojan app), then call check_intel again."
	case errors.As(err, &sub):
		msg := strings.TrimSpace(sub.Message)
		if msg != "" {
			msg += " "
		}
		return msg + "Dependency intel is a Pro/Team feature. Upgrade the plan in the Trojan app to use check_intel."
	}
	return "check_intel could not complete: " + err.Error()
}

func proposeLine(m intel.Match) string {
	sev := m.Severity
	if sev == "" {
		sev = "unrated"
	}
	sum := strings.TrimSpace(m.Advisory.Summary)
	if m.Kind == "malicious" {
		line := fmt.Sprintf("a release of %s you have installed (%s) was published by an attacker (%s, %s)", m.Package, m.InstalledVersion, m.Advisory.ID, sev)
		if sum != "" {
			line += ": " + sum
		}
		return line + ". Status: matched, unproven. Remove it or pin to a version not on the list, then rotate any secrets this machine or CI could have exposed. Want me to confirm it is the listed release?"
	}
	line := fmt.Sprintf("%s %s matches a recent advisory (%s, %s)", m.Package, m.InstalledVersion, m.Advisory.ID, sev)
	if sum != "" {
		line += ": " + sum
	}
	line += ". Status: matched, unproven. Want me to check whether your app is actually affected, and fix it?"
	if m.FixedVersion != "" {
		line += " Fix: upgrade to " + m.FixedVersion + "."
	}
	return line
}

func handleCheckIntel(project projectFunc) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		recordActivity(clientName(ctx), "")
		projectPath, err := project(ctx, req)
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		res, err := intel.Check(ctx, projectPath, intel.Options{Client: newIntelClient()})
		if err != nil {
			return mcp.NewToolResultError(intelErrorText(err)), nil
		}

		store := loadIntelStore(projectPath)
		store.merge(res.Matches, time.Now().UTC())
		syncIntelFindings(projectPath, store)
		saveErr := store.save(projectPath)

		active := map[string]bool{}
		for _, m := range res.Matches {
			active[m.ID] = true
		}
		var views []matchView
		var b strings.Builder
		fmt.Fprintf(&b, "Trojan intel check: scanned %d installed packages from %s.\n", res.PackagesScanned, listOrNone(res.Lockfiles))
		if res.FromCache {
			fmt.Fprintf(&b, "Intel freshness: from the local cache fetched %s (server generated %s).\n", res.FetchedAt.Format(time.RFC3339), orUnknown(res.IntelGeneratedAt))
		} else {
			fmt.Fprintf(&b, "Intel freshness: fetched just now (server generated %s).\n", orUnknown(res.IntelGeneratedAt))
		}
		if res.UncoveredPackages > 0 {
			fmt.Fprintf(&b, "%d installed packages were not covered by the cached intel. Check again when online.\n", res.UncoveredPackages)
		}
		for _, w := range res.Warnings {
			fmt.Fprintf(&b, "Warning: %s\n", w)
		}
		if saveErr != nil {
			fmt.Fprintf(&b, "Warning: could not save match history: %s\n", saveErr)
		}
		b.WriteString("\n")

		n := 0
		for _, r := range store.Records {
			if !active[r.MatchID] {
				continue
			}
			views = append(views, viewOf(r))
			n++
			state := ""
			if r.Status != intelMatched {
				state = fmt.Sprintf(" [current status: %s]", r.Status)
			}
			fmt.Fprintf(&b, "%d. %s%s\n   match id: %s\n", n, proposeLine(r.Match), state, r.MatchID)
		}
		if n == 0 {
			fmt.Fprintf(&b, "No installed package matches an advisory in the intel as of %s. This only covers the lockfiles and advisories above; it is not a statement that the project is safe.\n", orUnknown(res.IntelGeneratedAt))
		} else {
			b.WriteString("\nThese are matches, not verdicts. To move one forward, call prove_intel_match with its match id. Do not tell the user their app is vulnerable until it is confirmed.\n")
		}
		b.WriteString("\n" + intelContrast + "\n")
		if views == nil {
			views = []matchView{}
		}
		payload, _ := json.MarshalIndent(map[string]any{
			"packages_scanned": res.PackagesScanned, "lockfiles": res.Lockfiles,
			"intel_generated_at": res.IntelGeneratedAt, "from_cache": res.FromCache,
			"fetched_at": res.FetchedAt, "uncovered_packages": res.UncoveredPackages,
			"warnings": res.Warnings, "matches": views,
		}, "", "  ")
		b.WriteString("\n```json\n" + string(payload) + "\n```")
		return mcp.NewToolResultText(b.String()), nil
	}
}

func listOrNone(l []string) string {
	if len(l) == 0 {
		return "no lockfiles"
	}
	return strings.Join(l, ", ")
}

func orUnknown(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}

// ── prove_intel_match ───────────────────────────────────────────────────────

// upgradeCommand is the package-manager command that installs the fixed
// version, inferred from the lockfile the package was found in.
func upgradeCommand(m intel.Match) string {
	if m.FixedVersion == "" {
		return ""
	}
	pkg, v := m.Package, m.FixedVersion
	lock := strings.ToLower(filepath.Base(m.Lockfile))
	switch {
	case lock == "package-lock.json" || lock == "npm-shrinkwrap.json":
		return fmt.Sprintf("npm install %s@%s", pkg, v)
	case lock == "pnpm-lock.yaml":
		return fmt.Sprintf("pnpm add %s@%s", pkg, v)
	case lock == "yarn.lock":
		return fmt.Sprintf("yarn add %s@%s", pkg, v)
	case lock == "bun.lock":
		return fmt.Sprintf("bun add %s@%s", pkg, v)
	case lock == "poetry.lock":
		return fmt.Sprintf("poetry add \"%s>=%s\"", pkg, v)
	case lock == "uv.lock":
		return fmt.Sprintf("uv add \"%s>=%s\"", pkg, v)
	case lock == "pipfile.lock":
		return fmt.Sprintf("pipenv install \"%s>=%s\"", pkg, v)
	case strings.HasSuffix(lock, ".txt"):
		return fmt.Sprintf("pip install \"%s>=%s\" (and update the pin in %s)", pkg, v, filepath.Base(m.Lockfile))
	}
	if m.Ecosystem == intel.EcosystemPyPI {
		return fmt.Sprintf("pip install \"%s>=%s\"", pkg, v)
	}
	return fmt.Sprintf("npm install %s@%s", pkg, v)
}

func upgradeNote(m intel.Match) string {
	cmd := upgradeCommand(m)
	if cmd == "" {
		return "No fixed version is listed yet; check the advisory for a workaround."
	}
	s := "Upgrade with: " + cmd + "."
	if !m.Direct {
		s += " This package is pulled in by another dependency, so you may need to upgrade the parent package or add an override/resolution instead."
	}
	return s
}

// installedStillAffected re-parses the lockfiles and reports whether the
// match's advisory still applies: "same" (exact version still installed and in
// range), "other" (a different affected version is installed now), or "gone".
func installedStillAffected(project string, m intel.Match) (state string, versions []string, err error) {
	pkgs, _, _, err := intel.ParseProjectWithWarnings(project)
	if err != nil {
		return "", nil, err
	}
	for _, mm := range intel.MatchAdvisories(pkgs, []intel.Advisory{m.Advisory}) {
		if mm.ID == m.ID {
			return "same", nil, nil
		}
		if mm.Package == m.Package && mm.Ecosystem == m.Ecosystem {
			versions = append(versions, mm.InstalledVersion)
		}
	}
	if len(versions) > 0 {
		return "other", versions, nil
	}
	return "gone", nil, nil
}

func installedVersions(project string, m intel.Match) string {
	pkgs, _, _, err := intel.ParseProjectWithWarnings(project)
	if err != nil {
		return "no longer installed"
	}
	var vs []string
	for _, p := range pkgs {
		if p.Ecosystem == m.Ecosystem && strings.EqualFold(p.Name, m.Package) {
			vs = append(vs, p.Version)
		}
	}
	if len(vs) == 0 {
		return "not installed any more"
	}
	return "now installed: " + strings.Join(vs, ", ")
}

func (r *intelRecord) addProof(kind, result, detail string) {
	r.ProofKind = kind
	r.ProofHistory = append(r.ProofHistory, proofEvent{At: time.Now().UTC(), Kind: kind, Result: result, Detail: detail})
}

func handleProveIntelMatch(project projectFunc) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		recordActivity(clientName(ctx), "")
		projectPath, err := project(ctx, req)
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		id, err := req.RequireString("match_id")
		if err != nil {
			return mcp.NewToolResultError("missing required parameter: match_id (from check_intel)"), nil
		}
		store := loadIntelStore(projectPath)
		rec := store.find(id)
		if rec == nil {
			return mcp.NewToolResultError(fmt.Sprintf("No saved match %q. Run check_intel first and use a match id from its output.", id)), nil
		}
		out, isErr := proveRecord(ctx, req, projectPath, store, rec)
		if err := store.save(projectPath); err != nil {
			out += "\n(Warning: could not save match history: " + err.Error() + ")"
		}
		if isErr {
			return mcp.NewToolResultError(out), nil
		}
		return mcp.NewToolResultText(out), nil
	}
}

func proveRecord(ctx context.Context, req mcp.CallToolRequest, project string, store *intelStore, rec *intelRecord) (string, bool) {
	m := rec.Match
	label := fmt.Sprintf("%s %s (%s)", m.Package, m.InstalledVersion, m.Advisory.ID)

	if rec.Status == intelResolved {
		return fmt.Sprintf("%s is no longer in the lockfiles (resolved %s). Run check_intel to refresh.", label, rec.ResolvedAt.Format(time.RFC3339)), false
	}

	// Step 1, always, free: is the affected version still installed?
	state, others, err := installedStillAffected(project, m)
	if err != nil {
		return "Could not re-read the lockfiles: " + err.Error(), true
	}
	switch state {
	case "gone":
		rec.Status = intelFixed
		detail := fmt.Sprintf("installed %s is outside the affected range (%s)", m.Package, installedVersions(project, m))
		rec.addProof("version", intelFixed, detail)
		resolveIntelFinding(project, rec)
		return fmt.Sprintf("FIXED: %s. %s is outside the affected range of %s. Status: fixed.", label, detail, m.Advisory.ID), false
	case "other":
		return fmt.Sprintf("%s changed: %s is now installed at %s, which is still in the affected range of %s. Run check_intel to refresh the matches, then prove the new one.", label, m.Package, strings.Join(others, ", "), m.Advisory.ID), false
	}

	// A hosted test already running or finished for this match.
	if rec.Status == intelProving {
		return readHostedProof(project, store, rec)
	}
	if rec.Status == intelConfirmed || rec.Status == intelNotAffected {
		return describeSettled(rec), false
	}

	// Malicious releases need no exploit proof: the installed release is the problem.
	if m.Kind == "malicious" {
		rec.Status = intelConfirmed
		rec.addProof("version", intelConfirmed, "installed release is listed as published by an attacker")
		note := promoteConfirmed(project, store, rec)
		return fmt.Sprintf("CONFIRMED: %s. The installed release is on the list of releases published by an attacker. Remove it or pin to a version not on the list (%s), and rotate any secrets that this machine or CI could have exposed.%s", label, upgradeNoteMalicious(m), note), false
	}

	targetURL := strings.TrimSpace(req.GetString("target_url", ""))
	if m.ProofAvailable && targetURL != "" {
		return startHostedProof(ctx, req, project, rec, targetURL)
	}

	rec.addProof("version", "in_range", "installed version is in the affected range")
	if m.ProofAvailable {
		rec.ProofKind = "version"
		return fmt.Sprintf("%s: installed %s is in the affected range, but whether your code is affected has not been tested. Status stays matched, unproven.\n"+
			"A Trojan playbook can test this against your running app. That spends Trojan credits and needs your site's URL: call prove_intel_match again with target_url and, after the owner says yes, owner_confirmed=true.\n"+
			"Or just fix it. %s Then call prove_intel_match again to confirm the fix.", label, m.InstalledVersion, upgradeNote(m)), false
	}
	rec.Status = intelConfirmed
	rec.ProofKind = "version"
	note := promoteConfirmed(project, store, rec)
	return fmt.Sprintf("CONFIRMED (version only): %s. Your installed version is in the affected range; whether your code is affected was not tested (Trojan has no playbook for this advisory yet).\n%s%s", label, upgradeNote(m), note), false
}

func upgradeNoteMalicious(m intel.Match) string {
	if m.FixedVersion != "" {
		return "e.g. " + m.FixedVersion
	}
	return "check the advisory for safe versions"
}

func describeSettled(rec *intelRecord) string {
	m := rec.Match
	label := fmt.Sprintf("%s %s (%s)", m.Package, m.InstalledVersion, m.Advisory.ID)
	if rec.Status == intelNotAffected {
		return fmt.Sprintf("%s: Trojan's hosted test did not reproduce this against your app (status: not_affected). The installed version is still in the advisory's range, so upgrading is still sensible. %s", label, upgradeNote(m))
	}
	return fmt.Sprintf("%s is already confirmed (proof: %s). It is a finding now (id %s): fix it, then run verify_fix on it. %s", label, rec.ProofKind, rec.FindingID, upgradeNote(m))
}

// ── hosted verification ─────────────────────────────────────────────────────

func startHostedProof(ctx context.Context, req mcp.CallToolRequest, project string, rec *intelRecord, targetURL string) (string, bool) {
	m := rec.Match
	label := fmt.Sprintf("%s %s (%s)", m.Package, m.InstalledVersion, m.Advisory.ID)
	if !req.GetBool("owner_confirmed", false) {
		return fmt.Sprintf("Confirmation needed before anything starts. Trojan has a playbook (%s) that can check whether %s actually affects your app at %s. "+
			"This runs Trojan's hosted penetration test against that site, spends the user's Trojan credits and takes several minutes (about 365 tokens is typical). "+
			"Testing a site you don't own is illegal. Ask the user: \"Do you own %s or have permission to test it, and is it OK to spend credits?\" "+
			"Only if they say yes, call prove_intel_match again with the same arguments plus owner_confirmed=true. Nothing has been started.",
			slugOf(m), label, targetURL, targetURL), false
	}
	tmpl, _ := json.Marshal(attackTemplateFor(m))
	args := map[string]any{
		"url": targetURL, "owner_confirmed": true, "project_path": project,
		"attack_template": string(tmpl),
	}
	res, err := startHostedTest(ctx, args)
	if err != nil {
		return "could not start the test: " + err.Error(), true
	}
	text := resultText(res)
	if res.IsError {
		return "The hosted test did not start (nothing was charged): " + text, true
	}
	now := time.Now().UTC()
	rec.Status, rec.TestURL, rec.TestStarted = intelProving, targetURL, &now
	rec.TestID = hostedTestID(targetURL, now)
	if siteDir, e := normalizer.WebsiteDir(normalizeSiteURL(targetURL)); e == nil {
		if r := loadRun(siteDir); r != nil {
			rec.TestStarted = &r.StartedAt
			rec.TestID = hostedTestID(targetURL, r.StartedAt)
		}
	}
	rec.addProof("hosted_test", "started", "playbook "+slugOf(m)+" via test "+rec.TestID)
	return fmt.Sprintf("Started Trojan's hosted verification for %s (playbook %s). It uses the user's Trojan credits. Test id: %s. Status: proving.\n"+
		"Follow progress with website_test_status(url=%q, wait=true), then call prove_intel_match again with this match id to record the result.\n%s",
		label, slugOf(m), rec.TestID, targetURL, text), false
}

func hostedTestID(target string, started time.Time) string {
	return fmt.Sprintf("%s@%d", safeName(strings.TrimPrefix(strings.TrimPrefix(normalizeSiteURL(target), "https://"), "http://")), started.Unix())
}

func slugOf(m intel.Match) string {
	if m.Advisory.PlaybookID != nil {
		return *m.Advisory.PlaybookID
	}
	return ""
}

func resultText(res *mcp.CallToolResult) string {
	var parts []string
	for _, c := range res.Content {
		if t, ok := c.(mcp.TextContent); ok {
			parts = append(parts, t.Text)
		}
	}
	return strings.Join(parts, "\n")
}

// attackTemplateFor builds the run's playbook context from the advisory. The
// existing --attack-template flag takes {title, technique, body}; it has no
// slug-resolution hook, so the slug travels in the title and body while the
// advisory text supplies the substance. The engine treats it as guidance that
// the safety contract overrides.
func attackTemplateFor(m intel.Match) map[string]any {
	details := ""
	if m.Advisory.Details != nil {
		details = *m.Advisory.Details
	}
	if len(details) > 3000 {
		details = details[:3000]
	}
	body := fmt.Sprintf("Check whether this app is actually affected by advisory %s in the dependency %s (installed %s).\n"+
		"Attack Market playbook slug: %s.\nAdvisory summary: %s\nAdvisory details:\n%s\n"+
		"Probe only the running app. Report a finding only if you can demonstrate the behavior the advisory describes; mention %s in the finding title.",
		m.Advisory.ID, m.Package, m.InstalledVersion, slugOf(m), m.Advisory.Summary, details, m.Advisory.ID)
	return map[string]any{
		"title":     fmt.Sprintf("Verify %s (%s)", m.Advisory.ID, slugOf(m)),
		"technique": []string{"dependency advisory"},
		"body":      body,
	}
}

// readHostedProof reads the finished hosted test through the existing run and
// findings code and promotes the match.
func readHostedProof(project string, store *intelStore, rec *intelRecord) (string, bool) {
	m := rec.Match
	label := fmt.Sprintf("%s %s (%s)", m.Package, m.InstalledVersion, m.Advisory.ID)
	siteDir, err := normalizer.WebsiteDir(normalizeSiteURL(rec.TestURL))
	if err != nil {
		return err.Error(), true
	}
	r := loadRun(siteDir)
	if r == nil || (rec.TestStarted != nil && !r.StartedAt.Equal(*rec.TestStarted)) {
		return fmt.Sprintf("The hosted test %s for %s is not visible any more (a newer test of %s replaced it). Call prove_intel_match again with target_url and owner_confirmed to rerun it.", rec.TestID, label, rec.TestURL), false
	}
	switch r.State {
	case "running":
		return fmt.Sprintf("Test %s for %s is still running. Wait with website_test_status(url=%q, wait=true), then call prove_intel_match again.", rec.TestID, label, rec.TestURL), false
	case "finished":
	default:
		rec.Status = intelMatched
		rec.addProof("hosted_test", "inconclusive", "test failed: "+r.Reason)
		return fmt.Sprintf("The hosted test %s failed (%s), so %s stays matched, unproven. Check website_test_status for details.", rec.TestID, orUnknown(r.Reason), label), false
	}
	scan, err := loadLatestScan(siteDir)
	if err != nil {
		return "Test finished but its findings can't be read: " + err.Error(), true
	}
	if hit := findAdvisoryFinding(scan.Findings, m); hit != nil {
		rec.Status = intelConfirmed
		rec.addProof("hosted_test", intelConfirmed, "test finding "+hit.ID+": "+hit.Title)
		note := promoteConfirmed(project, store, rec)
		return fmt.Sprintf("CONFIRMED by Trojan's hosted test: %s. The test demonstrated the behavior (finding %s: %s).\n%s%s", label, hit.ID, hit.Title, upgradeNote(m), note), false
	}
	rec.Status = intelNotAffected
	rec.addProof("hosted_test", intelNotAffected, "the test finished without reproducing the advisory")
	return fmt.Sprintf("NOT REPRODUCED: Trojan's hosted test of %s finished and did not reproduce %s, so Trojan marks it not_affected for this app. That is evidence, not a guarantee. The installed version is still in the advisory's range, so upgrading is still sensible. %s", rec.TestURL, m.Advisory.ID, upgradeNote(m)), false
}

func findAdvisoryFinding(fs []normalizer.Finding, m intel.Match) *normalizer.Finding {
	needles := []string{strings.ToLower(m.Advisory.ID)}
	for _, a := range m.Advisory.Aliases {
		needles = append(needles, strings.ToLower(a))
	}
	for i := range fs {
		f := &fs[i]
		if f.Status == normalizer.StatusResolved || f.Status == normalizer.StatusSuppressed {
			continue
		}
		hay := strings.ToLower(f.Title + " " + f.RawMessage + " " + f.RuleID)
		for _, n := range needles {
			if n != "" && strings.Contains(hay, n) {
				return f
			}
		}
	}
	return nil
}

// ── promotion into the findings loop ────────────────────────────────────────

func intelSeverity(s string) normalizer.Severity {
	switch strings.ToLower(s) {
	case "critical":
		return normalizer.SeverityCritical
	case "high":
		return normalizer.SeverityHigh
	case "low":
		return normalizer.SeverityLow
	case "info", "informational":
		return normalizer.SeverityInfo
	}
	return normalizer.SeverityMedium
}

func intelFinding(rec *intelRecord) normalizer.Finding {
	m := rec.Match
	title := fmt.Sprintf("%s %s matches advisory %s", m.Package, m.InstalledVersion, m.Advisory.ID)
	if m.Kind == "malicious" {
		title = fmt.Sprintf("%s %s is a release published by an attacker (%s)", m.Package, m.InstalledVersion, m.Advisory.ID)
	}
	msg := strings.TrimSpace(m.Advisory.Summary)
	if rec.ProofKind == "version" && m.Kind != "malicious" {
		msg += " (Confirmed by version only: the installed version is in the affected range; whether the code is affected was not tested.)"
	}
	actions := []string{upgradeNote(m), "Then run verify_fix on this finding."}
	return normalizer.Finding{
		ID: rec.FindingID, Scanner: "trojan-intel", Category: "sca",
		Severity: intelSeverity(m.Severity), Title: title, RawMessage: strings.TrimSpace(msg),
		FilePath: m.Lockfile, RuleID: m.Advisory.ID, Status: normalizer.StatusOpen,
		Verdict: "confirmed", VerdictReason: "Trojan intel, proof: " + rec.ProofKind,
		Simply: title + ". " + msg, Actions: actions,
	}
}

// promoteConfirmed puts a confirmed match into the latest scan so get_findings,
// get_fixable_findings, mark_fixed and verify_fix see it, and drafts a
// playbook when the advisory has none.
func promoteConfirmed(project string, store *intelStore, rec *intelRecord) string {
	rec.FindingID = intelFindingID(rec.MatchID)
	syncIntelFindings(project, store)
	note := fmt.Sprintf("\nIt is now finding %s (see get_findings). After upgrading, run verify_fix on it.", rec.FindingID)
	if !rec.Match.ProofAvailable && rec.Match.Kind != "malicious" {
		if p, err := writePlaybookDraft(project, rec.Match); err == nil {
			rec.DraftPath = p
			note += fmt.Sprintf("\nTrojan has no playbook for %s yet, so a draft was saved for review at %s. It is not published.", rec.Match.Advisory.ID, p)
		}
	}
	return note
}

// syncIntelFindings makes sure every confirmed match has its finding in the
// latest scan (a fresh run_scan writes a new file that would otherwise drop
// it). Matches that are no longer confirmed get their finding resolved.
func syncIntelFindings(project string, store *intelStore) {
	var want []intelRecord
	for _, r := range store.Records {
		if r.FindingID != "" {
			want = append(want, r)
		}
	}
	if len(want) == 0 {
		return
	}
	scan, err := loadLatestScan(project)
	if err != nil {
		scan = &normalizer.ScanResult{Timestamp: time.Now(), ProjectPath: project}
	}
	changed := false
	for i := range want {
		r := &want[i]
		idx := -1
		for j := range scan.Findings {
			if scan.Findings[j].ID == r.FindingID {
				idx = j
			}
		}
		active := r.Status == intelConfirmed
		switch {
		case idx < 0 && active:
			scan.Findings = append(scan.Findings, intelFinding(r))
			changed = true
		case idx >= 0 && !active && scan.Findings[idx].Status == normalizer.StatusOpen &&
			(r.Status == intelFixed || r.Status == intelResolved || r.Status == intelNotAffected):
			scan.Findings[idx].Status = normalizer.StatusResolved
			changed = true
		}
	}
	if changed {
		writeIntelScan(project, scan) //nolint:errcheck // best effort; matches.json still holds the state
	}
}

func writeIntelScan(project string, scan *normalizer.ScanResult) error {
	if err := saveLatestScan(project, scan); err == nil {
		return nil
	}
	dir := filepath.Join(project, ".trojan", "scans")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(scan, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, time.Now().Format("2006-01-02T15-04-05")+".json"), data, 0o644)
}

func resolveIntelFinding(project string, rec *intelRecord) {
	if rec.FindingID == "" {
		return
	}
	scan, err := loadLatestScan(project)
	if err != nil {
		return
	}
	for i := range scan.Findings {
		if scan.Findings[i].ID == rec.FindingID {
			scan.Findings[i].Status = normalizer.StatusResolved
		}
	}
	saveLatestScan(project, scan) //nolint:errcheck
}

// verifyIntelFinding handles verify_fix for a trojan-intel finding: it re-runs
// the version check against the lockfiles. handled=false means the id is not
// an intel finding.
func verifyIntelFinding(project, findingID string) (text string, handled bool) {
	store := loadIntelStore(project)
	rec := store.findByFindingID(findingID)
	if rec == nil {
		return "", false
	}
	m := rec.Match
	state, others, err := installedStillAffected(project, m)
	if err != nil {
		return "couldn't confirm the fix right now: " + err.Error(), true
	}
	if state == "gone" {
		rec.Status = intelFixed
		rec.addProof("version", intelFixed, "re-check after upgrade: "+installedVersions(project, m))
		resolveIntelFinding(project, rec)
		store.save(project) //nolint:errcheck
		return fmt.Sprintf("VERIFIED FIXED: %s is no longer installed at an affected version (%s) for %s. Finding %s is marked fixed.", m.Package, installedVersions(project, m), m.Advisory.ID, findingID), true
	}
	at := m.InstalledVersion
	if state == "other" {
		at = strings.Join(others, ", ")
	}
	return fmt.Sprintf("NOT FIXED: %s %s is still in the affected range of %s. %s", m.Package, at, m.Advisory.ID, upgradeNote(m)), true
}

// ── Phase 4: playbook draft ─────────────────────────────────────────────────

// writePlaybookDraft saves an unpublished Attack Market template draft built
// from the advisory text only, in the market's story/prompt shape.
func writePlaybookDraft(project string, m intel.Match) (string, error) {
	details := ""
	if m.Advisory.Details != nil {
		details = *m.Advisory.Details
	}
	if len(details) > 4000 {
		details = details[:4000]
	}
	story := strings.TrimSpace(m.Advisory.Summary)
	if details != "" {
		story += "\n\n" + strings.TrimSpace(details)
	}
	draft := map[string]any{
		"slug":                "draft-" + strings.ToLower(safeName(m.Advisory.ID)),
		"title":               fmt.Sprintf("%s (%s)", m.Advisory.ID, m.Package),
		"technique":           []string{"dependency advisory"},
		"min_tier":            "passive",
		"breach_story":        story,
		"prompt_body":         fmt.Sprintf("Check whether this app exposes the behavior described in advisory %s for %s. Probe only the running app, stay within the rules of engagement, and report only what you can demonstrate.\n\nAdvisory: %s", m.Advisory.ID, m.Package, story),
		"status":              "draft",
		"needs_author_review": true,
		"source_advisory":     m.Advisory.ID,
		"generated_from":      "advisory text only; not tested, not published",
	}
	dir := filepath.Join(project, ".trojan", "intel", "playbook-drafts")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	path := filepath.Join(dir, safeName(m.Advisory.ID)+".json")
	data, err := json.MarshalIndent(draft, "", "  ")
	if err != nil {
		return "", err
	}
	return path, os.WriteFile(path, data, 0o644)
}
