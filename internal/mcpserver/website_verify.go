package mcpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"path/filepath"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"

	"github.com/dev-zeph/trojan/internal/dast/retest"
	"github.com/dev-zeph/trojan/internal/memory"
	"github.com/dev-zeph/trojan/internal/normalizer"
)

// ── Targeted website retest ──────────────────────────────────────────────────
//
// Re-checks website / pen-test findings by replaying the request recorded in
// each finding's Proof (internal/dast/retest), instead of rerunning the whole
// website test (credits + ~10 minutes). verify_fix routes website finding IDs
// here; retest_website_findings re-checks a whole test or a chosen list.

// hostOf returns the lowercased host of a tested site's URL.
func hostOf(rawURL string) string {
	if u, err := url.Parse(rawURL); err == nil && u.Host != "" {
		return strings.ToLower(u.Hostname())
	}
	return strings.ToLower(strings.TrimSpace(rawURL))
}

// findWebsiteFinding locates a finding by ID across every tested site, returning
// the site's folder and the finding. ok is false when no website test holds it.
func findWebsiteFinding(id string) (siteDir string, f normalizer.Finding, ok bool) {
	for _, dir := range normalizer.WebsiteSiteDirs() {
		scan, err := loadLatestScan(dir)
		if err != nil {
			continue
		}
		for _, cand := range scan.Findings {
			if cand.ID == id {
				return dir, cand, true
			}
		}
	}
	return "", normalizer.Finding{}, false
}

// retestWebsiteInDir re-checks findings in one site's latest scan. When ids is
// empty, every open finding is re-checked; otherwise only the listed IDs.
// Findings newly proven fixed are marked resolved in storage and recorded in
// that site's memory under the "fixed" kind. Returns the per-finding results.
func retestWebsiteInDir(ctx context.Context, siteDir string, ids []string) ([]retest.Result, error) {
	scan, err := loadLatestScan(siteDir)
	if err != nil {
		return nil, err
	}
	want := map[string]bool{}
	for _, id := range ids {
		want[id] = true
	}

	var targets []normalizer.Finding
	for _, f := range scan.Findings {
		if len(want) > 0 {
			if want[f.ID] {
				targets = append(targets, f)
			}
			continue
		}
		if f.Status == normalizer.StatusOpen {
			targets = append(targets, f)
		}
	}
	if len(targets) == 0 {
		if len(want) > 0 {
			return nil, fmt.Errorf("none of the given finding IDs are in the latest test of %s", scan.ProjectPath)
		}
		return []retest.Result{}, nil
	}

	rt, err := retest.New(retest.Options{Host: hostOf(scan.ProjectPath)})
	if err != nil {
		return nil, err
	}
	results := rt.RetestFindings(ctx, targets)

	// Apply "fixed" verdicts to storage + memory.
	changed := false
	for _, res := range results {
		if res.Verdict != retest.Fixed {
			continue
		}
		for i := range scan.Findings {
			if scan.Findings[i].ID != res.FindingID {
				continue
			}
			if scan.Findings[i].Status != normalizer.StatusResolved {
				scan.Findings[i].Status = normalizer.StatusResolved
				changed = true
				recordMemory(siteDir, scan.Findings[i], memory.KindFixed,
					fmt.Sprintf("retest: %s (%s)", res.Reason, scan.ProjectPath))
			}
		}
	}
	if changed {
		if err := saveLatestScan(siteDir, scan); err != nil {
			return results, fmt.Errorf("retest ran but saving the updated results failed: %w", err)
		}
	}
	return results, nil
}

// verifyFixWebsite handles verify_fix for a website finding ID: it retests that
// one finding and returns a verify-style message.
func verifyFixWebsite(ctx context.Context, siteDir, id string) *mcp.CallToolResult {
	results, err := retestWebsiteInDir(ctx, siteDir, []string{id})
	if err != nil {
		return mcp.NewToolResultError("retest failed: " + err.Error())
	}
	if len(results) == 0 {
		return mcp.NewToolResultError(fmt.Sprintf("finding %q is not in the latest website test", id))
	}
	res := results[0]
	switch res.Verdict {
	case retest.Fixed:
		return mcp.NewToolResultText(fmt.Sprintf("VERIFIED FIXED: %s. Finding %s is marked fixed.", res.Reason, id))
	case retest.Vulnerable:
		return mcp.NewToolResultText(fmt.Sprintf("NOT FIXED: %s. Finding %s is still open — look at the endpoint and try again.", res.Reason, id))
	default:
		return mcp.NewToolResultText(fmt.Sprintf("INCONCLUSIVE: %s.", res.Reason))
	}
}

// unifiedRow is one finding in the combined code + website list.
type unifiedRow struct {
	ID       string `json:"id"`
	Source   string `json:"source"` // "code" or "website"
	Site     string `json:"site,omitempty"`
	Severity string `json:"severity"`
	Title    string `json:"title"`
	Location string `json:"location,omitempty"`
	Status   string `json:"status"`
	Verdict  string `json:"verdict,omitempty"`
}

// handleGetAllFindings returns code and website findings in one list, each
// tagged with its source and a stable id that verify_fix accepts (expert
// feedback #11: a single list across both). The project's code scan is included
// when one is available; website findings always are.
func handleGetAllFindings(project projectFunc) func(context.Context, mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		recordActivity(clientName(ctx), "")
		minRank := severityRank[normalizer.Severity(strings.ToLower(req.GetString("min_severity", "info")))]
		all := strings.EqualFold(req.GetString("status", "open"), "all")

		keep := func(f normalizer.Finding) bool {
			if !all && f.Status != normalizer.StatusOpen {
				return false
			}
			return severityRank[f.Severity] >= minRank
		}

		rows := []unifiedRow{}

		// Code findings (best-effort: skip quietly when no project/scan).
		if projectPath, err := project(ctx, req); err == nil {
			if scan, err := loadLatestScan(projectPath); err == nil {
				for _, f := range scan.Findings {
					if !keep(f) {
						continue
					}
					loc := f.FilePath
					if f.LineNumber > 0 {
						loc = fmt.Sprintf("%s:%d", f.FilePath, f.LineNumber)
					}
					rows = append(rows, unifiedRow{ID: f.ID, Source: "code", Severity: string(f.Severity),
						Title: f.Title, Location: loc, Status: string(f.Status), Verdict: f.Verdict})
				}
			}
		}

		// Website findings across every tested site.
		for _, dir := range normalizer.WebsiteSiteDirs() {
			scan, err := loadLatestScan(dir)
			if err != nil {
				continue
			}
			for _, f := range scan.Findings {
				if !keep(f) {
					continue
				}
				rows = append(rows, unifiedRow{ID: f.ID, Source: "website", Site: scan.ProjectPath,
					Severity: string(f.Severity), Title: f.Title, Location: f.FilePath, Status: string(f.Status), Verdict: f.Verdict})
			}
		}

		out, err := json.MarshalIndent(map[string]any{
			"total":    len(rows),
			"findings": rows,
		}, "", "  ")
		if err != nil {
			return mcp.NewToolResultError("failed to serialize findings"), nil
		}
		return mcp.NewToolResultText(string(out)), nil
	}
}

// resolveSiteDir maps a URL or host to a tested site's folder. An empty want
// returns the most recently tested site. It returns a clear error when nothing
// matches so callers can relay it verbatim.
func resolveSiteDir(want string) (string, error) {
	dirs := normalizer.WebsiteSiteDirs()
	if len(dirs) == 0 {
		return "", fmt.Errorf("no website tests yet — test a live site first, then retest its findings")
	}
	want = strings.TrimSpace(want)
	if want == "" {
		return dirs[0], nil
	}
	if !strings.Contains(want, "://") {
		want = normalizeSiteURL(want)
	}
	if d, err := normalizer.WebsiteDir(want); err == nil {
		for _, cand := range dirs {
			if cand == d || strings.HasPrefix(filepath.Base(cand), filepath.Base(d)) {
				return cand, nil
			}
		}
	}
	return "", fmt.Errorf("Trojan hasn't tested %s yet; run list_website_tests to see tested sites", want)
}

// RetestWebsiteSummary is the JSON shape returned to the CLI / desktop.
type RetestWebsiteSummary struct {
	Site         string          `json:"site"`
	Retested     int             `json:"retested"`
	Fixed        int             `json:"fixed"`
	StillOpen    int             `json:"still_open"`
	Inconclusive int             `json:"inconclusive"`
	Results      []retest.Result `json:"results"`
}

// RetestWebsite re-checks findings in a tested site's latest results by
// replaying each finding's proof. siteURLOrHost selects the site (empty = most
// recent); ids narrows to specific findings (empty = all open). Exported for
// the CLI (`trojan dast retest`). Fixed findings are marked resolved and
// recorded in that site's memory.
func RetestWebsite(ctx context.Context, siteURLOrHost string, ids []string) (RetestWebsiteSummary, error) {
	siteDir, err := resolveSiteDir(siteURLOrHost)
	if err != nil {
		return RetestWebsiteSummary{}, err
	}
	results, err := retestWebsiteInDir(ctx, siteDir, ids)
	if err != nil {
		return RetestWebsiteSummary{}, err
	}
	sum := RetestWebsiteSummary{Retested: len(results), Results: results}
	if scan, err := loadLatestScan(siteDir); err == nil {
		sum.Site = scan.ProjectPath
	}
	for _, r := range results {
		switch r.Verdict {
		case retest.Fixed:
			sum.Fixed++
		case retest.Vulnerable:
			sum.StillOpen++
		default:
			sum.Inconclusive++
		}
	}
	return sum, nil
}

func handleRetestWebsiteFindings(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	recordActivity(clientName(ctx), "")

	var ids []string
	for _, s := range req.GetStringSlice("ids", nil) {
		if strings.TrimSpace(s) != "" {
			ids = append(ids, strings.TrimSpace(s))
		}
	}

	// Resolve the site: an explicit url, else the site that holds the first id,
	// else the most recently tested site.
	want := strings.TrimSpace(req.GetString("url", ""))
	var siteDir string
	if want != "" {
		dir, err := resolveSiteDir(want)
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		siteDir = dir
	} else if len(ids) > 0 {
		if dir, _, ok := findWebsiteFinding(ids[0]); ok {
			siteDir = dir
		}
	}
	if siteDir == "" {
		dir, err := resolveSiteDir("")
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		siteDir = dir
	}

	results, err := retestWebsiteInDir(ctx, siteDir, ids)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	scan, _ := loadLatestScan(siteDir)
	site := ""
	if scan != nil {
		site = scan.ProjectPath
	}
	fixed, stillOpen, inconclusive := 0, 0, 0
	for _, r := range results {
		switch r.Verdict {
		case retest.Fixed:
			fixed++
		case retest.Vulnerable:
			stillOpen++
		default:
			inconclusive++
		}
	}
	out, _ := json.MarshalIndent(map[string]any{
		"site":         site,
		"retested":     len(results),
		"fixed":        fixed,
		"still_open":   stillOpen,
		"inconclusive": inconclusive,
		"results":      results,
	}, "", "  ")
	return mcp.NewToolResultText(string(out)), nil
}
