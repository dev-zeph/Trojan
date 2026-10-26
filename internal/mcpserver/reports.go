package mcpserver

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"

	"github.com/dev-zeph/trojan/internal/config"
	"github.com/dev-zeph/trojan/internal/normalizer"
)

// ── generate_report ──────────────────────────────────────────────────────────
//
// Calls the same edge functions as the desktop app's report buttons
// (threat-lab, compliance-lab, pentest-report), with the same payloads, then
// writes the result as Markdown + HTML so the AI tool can show, attach or send
// it. The edge functions meter credits server-side.

// edgeBase is a var so tests can point it at a stub server.
var edgeBase = "https://dtmocojzvgsswjdsrmqr.supabase.co/functions/v1/"

// callEdge POSTs a base64-wrapped body ({"encoded": ...}; Cloudflare's WAF
// blocks raw code snippets) and decodes the JSON reply into out.
func callEdge(fn string, payload any, out any) error {
	cfg, err := config.LoadConfig()
	if err != nil || cfg.AccessToken == "" {
		return errors.New("sign in to the Trojan desktop app first")
	}
	inner, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	body, _ := json.Marshal(map[string]string{"encoded": base64.StdEncoding.EncodeToString(inner)})
	req, err := http.NewRequest(http.MethodPost, edgeBase+fn, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+cfg.AccessToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := (&http.Client{Timeout: 3 * time.Minute}).Do(req)
	if err != nil {
		return fmt.Errorf("report request failed: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		return json.NewDecoder(resp.Body).Decode(out)
	case http.StatusPaymentRequired:
		return errors.New("not enough Trojan credits for this report. The user can top up in the Trojan app")
	case http.StatusUnauthorized, http.StatusForbidden:
		return errors.New("Trojan rejected the sign-in. Ask the user to sign in again in the Trojan app")
	case http.StatusTooManyRequests:
		return errors.New("daily report limit reached. Try again tomorrow")
	}
	var e struct {
		Error string `json:"error"`
	}
	json.NewDecoder(resp.Body).Decode(&e) //nolint:errcheck
	return fmt.Errorf("report failed (status %d): %s", resp.StatusCode, e.Error)
}

func familiarity() int {
	if cfg, err := config.LoadConfig(); err == nil {
		return cfg.Familiarity
	}
	return 1
}

// report is rendered to both Markdown and HTML.
type report struct {
	Title, Subtitle string
	Grade           string
	Score           int
	Sections        []reportSection
}

type reportSection struct {
	Heading string
	Text    string
	Items   []string
}

func handleGenerateReport(project projectFunc) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		kind := strings.ToLower(strings.TrimSpace(req.GetString("kind", "")))
		projectPath, perr := project(ctx, req)

		var rep *report
		var err error
		outDir := ""
		switch kind {
		case "security", "compliance":
			if perr != nil {
				return mcp.NewToolResultError(perr.Error()), nil
			}
			scan, lerr := loadLatestScan(projectPath)
			if lerr != nil {
				return mcp.NewToolResultError(lerr.Error()), nil
			}
			if kind == "security" {
				rep, err = securityReport(projectPath, scan)
			} else {
				rep, err = complianceReport(projectPath, scan)
			}
			outDir = projectPath
		case "website":
			rep, outDir, err = websiteReport(req.GetString("url", ""))
			if perr == nil {
				outDir = projectPath // keep it with the code it's about
			}
		default:
			return mcp.NewToolResultError(`kind must be "security", "compliance" or "website"`), nil
		}
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}

		md, htmlPath, err := writeReport(outDir, kind, rep)
		if err != nil {
			return mcp.NewToolResultError("could not save the report: " + err.Error()), nil
		}
		return mcp.NewToolResultText(fmt.Sprintf("Report saved:\n- Markdown: %s\n- HTML (open in a browser, or print to PDF): %s\n\nGrade %s, score %d/100. Share these files, or summarise them for the user.",
			md, htmlPath, rep.Grade, rep.Score)), nil
	}
}

func securityReport(projectPath string, scan *normalizer.ScanResult) (*report, error) {
	var r struct {
		ThreatIndex   int      `json:"threat_index"`
		Grade         string   `json:"grade"`
		Verdict       string   `json:"verdict"`
		KeyRisks      []string `json:"key_risks"`
		AttackVectors []struct {
			Title, Severity, Description, Exploitability string
		} `json:"attack_vectors"`
		PriorityFixes []struct {
			Rank               int
			Title, Description string
			File               string
			Line               int
		} `json:"priority_fixes"`
		ComplianceSummary string `json:"compliance_summary"`
	}
	if err := callEdge("threat-lab", map[string]any{
		"project_path": projectPath, "findings": scan.Findings, "packages": scan.Packages, "user_familiarity": familiarity(),
	}, &r); err != nil {
		return nil, err
	}

	rep := &report{Title: "Security report", Subtitle: filepath.Base(projectPath), Grade: r.Grade, Score: clamp(100 - r.ThreatIndex)}
	rep.Sections = append(rep.Sections, reportSection{Heading: "Verdict", Text: r.Verdict})
	if len(r.KeyRisks) > 0 {
		rep.Sections = append(rep.Sections, reportSection{Heading: "Key risks", Items: r.KeyRisks})
	}
	var vectors []string
	for _, v := range r.AttackVectors {
		vectors = append(vectors, fmt.Sprintf("%s (%s, %s to exploit): %s", v.Title, v.Severity, v.Exploitability, v.Description))
	}
	if len(vectors) > 0 {
		rep.Sections = append(rep.Sections, reportSection{Heading: "How an attacker could get in", Items: vectors})
	}
	var fixes []string
	for _, f := range r.PriorityFixes {
		where := ""
		if f.File != "" {
			where = fmt.Sprintf(" (%s:%d)", f.File, f.Line)
		}
		fixes = append(fixes, fmt.Sprintf("%s%s: %s", f.Title, where, f.Description))
	}
	if len(fixes) > 0 {
		rep.Sections = append(rep.Sections, reportSection{Heading: "Fix first", Items: fixes})
	}
	if r.ComplianceSummary != "" {
		rep.Sections = append(rep.Sections, reportSection{Heading: "Compliance", Text: r.ComplianceSummary})
	}
	return rep, nil
}

func complianceReport(projectPath string, scan *normalizer.ScanResult) (*report, error) {
	type lic struct {
		Name    string `json:"name"`
		Version string `json:"version,omitempty"`
		License string `json:"license"`
	}
	var copyleft, weak []lic
	unknown, permissive := 0, 0
	for _, p := range scan.Packages {
		switch p.LicenseRisk {
		case "copyleft":
			copyleft = append(copyleft, lic{p.Name, p.Version, p.License})
		case "weak-copyleft":
			weak = append(weak, lic{Name: p.Name, License: p.License})
		case "permissive":
			permissive++
		default:
			unknown++
		}
	}
	type dt struct {
		Name           string `json:"name"`
		Category       string `json:"category"`
		DetectionCount int    `json:"detection_count"`
	}
	type tp struct {
		Name      string   `json:"name"`
		DataTypes []string `json:"data_types"`
	}
	privacy := map[string]any{"data_types": []dt{}, "third_party": []tp{}}
	if scan.Privacy != nil {
		var d []dt
		for _, x := range scan.Privacy.DataTypes {
			d = append(d, dt{x.Name, x.Category, x.DetectionCount})
		}
		var t []tp
		for _, x := range scan.Privacy.ThirdParty {
			t = append(t, tp{x.Name, x.DataTypes})
		}
		privacy = map[string]any{"data_types": d, "third_party": t}
	}

	var r struct {
		Grade            string   `json:"grade"`
		Score            int      `json:"score"`
		ExecutiveSummary string   `json:"executive_summary"`
		LicenseVerdict   string   `json:"license_verdict"`
		PrivacyVerdict   string   `json:"privacy_verdict"`
		Recommendations  []string `json:"recommendations"`
	}
	if err := callEdge("compliance-lab", map[string]any{
		"project_path": projectPath,
		"licenses": map[string]any{"total_packages": len(scan.Packages), "copyleft": copyleft, "weak_copyleft": weak,
			"unknown_count": unknown, "permissive_count": permissive},
		"privacy":          privacy,
		"user_familiarity": familiarity(),
	}, &r); err != nil {
		return nil, err
	}
	return &report{Title: "Compliance report", Subtitle: filepath.Base(projectPath), Grade: r.Grade, Score: r.Score, Sections: []reportSection{
		{Heading: "Summary", Text: r.ExecutiveSummary},
		{Heading: "Privacy", Text: r.PrivacyVerdict},
		{Heading: "Open-source licenses", Text: r.LicenseVerdict},
		{Heading: "Recommendations", Items: r.Recommendations},
	}}, nil
}

func websiteReport(rawURL string) (*report, string, error) {
	dirs := normalizer.WebsiteSiteDirs()
	if len(dirs) == 0 {
		return nil, "", errors.New("no website tests yet. Run start_website_test first")
	}
	dir := dirs[0]
	if strings.TrimSpace(rawURL) != "" {
		d, err := normalizer.WebsiteDir(normalizeSiteURL(rawURL))
		if err != nil || normalizer.LatestScanFile(d) == "" {
			return nil, "", fmt.Errorf("Trojan hasn't tested %s yet", rawURL)
		}
		dir = d
	}
	scan, err := loadLatestScan(dir)
	if err != nil {
		return nil, "", err
	}

	type pf struct {
		ID        string `json:"id"`
		Title     string `json:"title"`
		Severity  string `json:"severity"`
		Verdict   string `json:"verdict"`
		MatchedAt string `json:"matchedAt"`
		Evidence  string `json:"evidence"`
		Rationale string `json:"rationale"`
	}
	var findings []pf
	var listed []string
	for _, f := range scan.Findings {
		findings = append(findings, pf{f.ID, f.Title, strings.ToLower(string(f.Severity)), f.Verdict, f.FilePath, f.CodeSnippet, f.RawMessage})
		listed = append(listed, fmt.Sprintf("[%s] %s (%s)", strings.ToUpper(string(f.Severity)), f.Title, f.Status))
	}
	var r struct {
		Grade            string   `json:"grade"`
		Score            int      `json:"score"`
		ExecutiveSummary string   `json:"executive_summary"`
		Posture          string   `json:"posture"`
		KeyRisks         []string `json:"key_risks"`
		Recommendations  []string `json:"recommendations"`
	}
	if err := callEdge("pentest-report", map[string]any{
		"target": scan.ProjectPath, "findings": findings, "user_familiarity": familiarity(),
	}, &r); err != nil {
		return nil, "", err
	}
	return &report{Title: "Website security test", Subtitle: scan.ProjectPath + " · tested " + scan.Timestamp.Format("Jan 2, 2006"),
		Grade: r.Grade, Score: r.Score, Sections: []reportSection{
			{Heading: "Summary", Text: r.ExecutiveSummary},
			{Heading: "Overall posture", Text: r.Posture},
			{Heading: "Key risks", Items: r.KeyRisks},
			{Heading: "Recommendations", Items: r.Recommendations},
			{Heading: "Findings", Items: listed},
		}}, dir, nil
}

func clamp(n int) int {
	if n < 0 {
		return 0
	}
	if n > 100 {
		return 100
	}
	return n
}

// writeReport saves <dir>/.trojan/reports/<kind>-<timestamp>.{md,html}.
func writeReport(dir, kind string, r *report) (string, string, error) {
	outDir := filepath.Join(dir, ".trojan", "reports")
	if err := os.MkdirAll(outDir, 0755); err != nil {
		return "", "", err
	}
	stamp := time.Now().Format("2006-01-02-1504")
	base := filepath.Join(outDir, fmt.Sprintf("%s-%s", kind, stamp))
	generated := time.Now().Format("January 2, 2006")

	var md strings.Builder
	fmt.Fprintf(&md, "# %s\n\n%s · generated by Trojan on %s\n\n**Grade %s · %d/100**\n", r.Title, r.Subtitle, generated, r.Grade, r.Score)
	for _, s := range r.Sections {
		if s.Text == "" && len(s.Items) == 0 {
			continue
		}
		fmt.Fprintf(&md, "\n## %s\n\n", s.Heading)
		if s.Text != "" {
			md.WriteString(s.Text + "\n")
		}
		for _, it := range s.Items {
			md.WriteString("- " + it + "\n")
		}
	}

	var h strings.Builder
	e := html.EscapeString
	fmt.Fprintf(&h, `<!doctype html><html><head><meta charset="utf-8"><title>%s · %s</title><style>
body{font:15px/1.6 -apple-system,"Segoe UI",sans-serif;color:#17171a;max-width:760px;margin:48px auto;padding:0 24px}
h1{font-size:28px;margin:0}.sub{color:#56565e;margin:4px 0 20px}.grade{display:inline-block;background:#7c3aed;color:#fff;padding:6px 14px;font-weight:600}
h2{font-size:18px;margin-top:32px;border-bottom:1px solid #d3d0ca;padding-bottom:6px}li{margin:6px 0}@media print{body{margin:0}}
</style></head><body><h1>%s</h1><p class="sub">%s · generated by Trojan on %s</p><span class="grade">Grade %s · %d/100</span>`,
		e(r.Title), e(r.Subtitle), e(r.Title), e(r.Subtitle), generated, e(r.Grade), r.Score)
	for _, s := range r.Sections {
		if s.Text == "" && len(s.Items) == 0 {
			continue
		}
		fmt.Fprintf(&h, "<h2>%s</h2>", e(s.Heading))
		if s.Text != "" {
			fmt.Fprintf(&h, "<p>%s</p>", e(s.Text))
		}
		if len(s.Items) > 0 {
			h.WriteString("<ul>")
			for _, it := range s.Items {
				fmt.Fprintf(&h, "<li>%s</li>", e(it))
			}
			h.WriteString("</ul>")
		}
	}
	h.WriteString("</body></html>\n")

	if err := os.WriteFile(base+".md", []byte(md.String()), 0644); err != nil {
		return "", "", err
	}
	if err := os.WriteFile(base+".html", []byte(h.String()), 0644); err != nil {
		return "", "", err
	}
	return base + ".md", base + ".html", nil
}
