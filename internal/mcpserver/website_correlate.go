package mcpserver

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/dev-zeph/trojan/internal/ai"
	"github.com/dev-zeph/trojan/internal/greybox"
	"github.com/dev-zeph/trojan/internal/normalizer"
	"github.com/dev-zeph/trojan/internal/routes"
)

// ── Live (DAST) ↔ code (SAST) correlation ────────────────────────────────────
//
// A live finding names a URL; the code scan names file:line. When the caller
// tells us where the site's source is, we place each live finding on its
// handler (via the route table, or the file the agent named) and link the
// code findings that sit inside that handler, so an agent doesn't have to join
// the two views by hand. Read-time only: stored results are not modified, so
// tests saved before this existed benefit too.

// relatedFinding links a live finding to a code finding about the same code.
type relatedFinding struct {
	ID       string `json:"id"`
	Source   string `json:"source"` // always "code" for now
	Severity string `json:"severity"`
	Title    string `json:"title"`
	Location string `json:"location"`
	Relation string `json:"relation"` // "same_handler" | "rendered_template"
}

// correlator holds what's needed to place and link findings for one project.
type correlator struct {
	projectPath string
	src         *greybox.Source
	framework   string
	table       []routes.Route
	code        []normalizer.Finding // open code findings, FilePath made project-relative
	hasScan     bool
}

// newCorrelator returns nil when projectPath isn't a readable folder.
func newCorrelator(projectPath string) *correlator {
	if projectPath == "" {
		return nil
	}
	if info, err := os.Stat(projectPath); err != nil || !info.IsDir() {
		return nil
	}
	res := routes.NewResolver(projectPath)
	c := &correlator{
		projectPath: projectPath,
		src:         greybox.New(projectPath, res, nil),
		framework:   string(res.Framework()),
		table:       res.Routes(),
	}
	if scan, err := loadLatestScan(projectPath); err == nil {
		c.hasScan = true
		for _, f := range scan.Findings {
			if f.Status == normalizer.StatusSuppressed || f.LineNumber <= 0 || f.FilePath == "" {
				continue
			}
			f.FilePath = c.rel(f.FilePath)
			c.code = append(c.code, f)
		}
	}
	return c
}

// rel makes a code finding's path project-relative (scanners report a mix of
// absolute and relative paths).
func (c *correlator) rel(p string) string {
	if filepath.IsAbs(p) {
		if r, err := filepath.Rel(c.projectPath, p); err == nil && !strings.HasPrefix(r, "..") {
			return filepath.ToSlash(r)
		}
	}
	return filepath.ToSlash(strings.TrimPrefix(p, "./"))
}

// place fills a live finding's source location (and code context) when it has
// none: a file the agent named is kept only if it is really in the project;
// otherwise the URL is resolved through the route table.
func (c *correlator) place(f *normalizer.Finding) {
	if f.SourceFile != "" {
		if rel, ok := c.src.ProjectFile(f.SourceFile); ok {
			f.SourceFile = rel
		} else {
			f.SourceFile, f.SourceLine = "", 0
		}
	}
	if f.SourceFile == "" {
		if file, line, ok := c.src.Locate("", f.URL); ok {
			f.SourceFile, f.SourceLine = file, line
		}
	}
	if f.SourceFile == "" {
		return
	}
	if f.SurroundingCode == "" {
		f.SurroundingCode = c.src.HandlerSource(f.SourceFile, f.SourceLine)
	}
	if f.Language == "" {
		f.Language = ai.DetectLanguage(f.SourceFile)
	}
	if f.Framework == "" {
		f.Framework = c.framework
	}
}

// handlerSpan returns the 1-indexed line range [start, end] of the handler that
// starts at line in file: up to the line before the next route in the same
// file, or the end of the file. line 0 (file-routed handlers) spans the file.
func (c *correlator) handlerSpan(file string, line int) (int, int) {
	if line <= 0 {
		return 1, 1 << 30
	}
	end := 1 << 30
	for _, r := range c.table {
		if filepath.ToSlash(r.HandlerFile) == file && r.HandlerLine > line && r.HandlerLine-1 < end {
			end = r.HandlerLine - 1
		}
	}
	return line, end
}

var renderTemplateRe = regexp.MustCompile(`render_template\s*\(\s*['"]([^'"]+)['"]`)

// related lists the code findings inside a placed live finding's handler, plus
// findings in templates that handler renders (Flask render_template).
func (c *correlator) related(f normalizer.Finding) []relatedFinding {
	if f.SourceFile == "" || len(c.code) == 0 {
		return nil
	}
	start, end := c.handlerSpan(f.SourceFile, f.SourceLine)
	templates := map[string]bool{}
	if f.SourceLine > 0 {
		if body := c.lines(f.SourceFile, start, end); body != "" {
			for _, m := range renderTemplateRe.FindAllStringSubmatch(body, -1) {
				templates[m[1]] = true
			}
		}
	}

	var out []relatedFinding
	for _, cf := range c.code {
		rel := ""
		switch {
		case cf.FilePath == f.SourceFile && cf.LineNumber >= start && cf.LineNumber <= end:
			rel = "same_handler"
		case len(templates) > 0 && templates[templateName(cf.FilePath)]:
			rel = "rendered_template"
		default:
			continue
		}
		out = append(out, relatedFinding{
			ID: cf.ID, Source: "code", Severity: string(cf.Severity), Title: cf.Title,
			Location: fmt.Sprintf("%s:%d", cf.FilePath, cf.LineNumber), Relation: rel,
		})
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Relation != out[j].Relation {
			return out[i].Relation == "same_handler"
		}
		return severityRank[normalizer.Severity(out[i].Severity)] > severityRank[normalizer.Severity(out[j].Severity)]
	})
	return out
}

// templateName maps "templates/admin/x.html" to the name render_template uses
// ("admin/x.html"); other paths pass through.
func templateName(p string) string {
	if i := strings.Index(p, "templates/"); i >= 0 {
		return p[i+len("templates/"):]
	}
	return p
}

// lines returns lines [start, end] of a project file ("" on error).
func (c *correlator) lines(file string, start, end int) string {
	data, err := os.ReadFile(filepath.Join(c.projectPath, filepath.FromSlash(file)))
	if err != nil {
		return ""
	}
	ls := strings.Split(string(data), "\n")
	if start < 1 {
		start = 1
	}
	if end > len(ls) {
		end = len(ls)
	}
	if start > end {
		return ""
	}
	return strings.Join(ls[start-1:end], "\n")
}

// codeScanNote explains an empty related_findings for a placed finding, which
// is itself useful: the live test caught something the code scan cannot see.
func (c *correlator) codeScanNote(f normalizer.Finding, related []relatedFinding) string {
	if f.SourceFile == "" || len(related) > 0 {
		return ""
	}
	if !c.hasScan {
		return "No code scan of project_path yet, so there are no code findings to link. Run run_scan to get them."
	}
	return fmt.Sprintf("The code scan has no finding in this handler (%s). Only the live test caught this, so fix it from the evidence here.", sourceLocation(f))
}
