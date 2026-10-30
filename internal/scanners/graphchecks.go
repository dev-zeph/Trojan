package scanners

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/dev-zeph/trojan/internal/graph"
	"github.com/dev-zeph/trojan/internal/normalizer"
	"github.com/dev-zeph/trojan/internal/rag"
)

// GraphChecks reports the flaws Trojan's own code graph can show end to end
// (graph.Detect): request input built into a SQL string, and public input
// stored in a table and later rendered as raw HTML. Rule packs miss both in
// typical Next.js code: the request arrives through req.json() rather than an
// Express req, and the stored-XSS chain spans a public route, a table, an
// admin API route and a client page.
//
// It needs no external binary and builds the graph in memory, so a scan never
// writes .trojan/graph.db through this path (enrichWithGraph does that).
type GraphChecks struct{}

func (GraphChecks) Name() string      { return "trojan" }
func (GraphChecks) Category() string  { return "sast" }
func (GraphChecks) IsAvailable() bool { return true }

func (GraphChecks) Run(projectPath string) ([]normalizer.Finding, error) {
	root, err := filepath.Abs(projectPath)
	if err != nil {
		return nil, err
	}
	files, err := rag.WalkSource(root)
	if err != nil {
		return nil, fmt.Errorf("trojan graph checks: walk %s: %w", projectPath, err)
	}
	if len(files) == 0 {
		return []normalizer.Finding{}, nil
	}
	g, err := graph.BuildFromFilesRoot(root, files)
	if err != nil {
		return nil, fmt.Errorf("trojan graph checks: build graph: %w", err)
	}
	return detectionsToFindings(projectPath, root, graph.Detect(g, root)), nil
}

// detectionsToFindings maps graph detections to findings. FilePath is
// projectPath joined with the file's path relative to the project root, the
// same shape Semgrep reports, so dedup and the report UI treat them alike.
func detectionsToFindings(projectPath, root string, ds []graph.Detection) []normalizer.Finding {
	out := make([]normalizer.Finding, 0, len(ds))
	for _, d := range ds {
		rel := d.Sink.Key
		if i := strings.Index(rel, "#"); i >= 0 {
			rel = rel[:i]
		}
		abs := d.Sink.File
		if abs == "" || !filepath.IsAbs(abs) {
			abs = filepath.Join(root, filepath.FromSlash(rel))
		}
		if rel == "" {
			if r, err := filepath.Rel(root, abs); err == nil {
				rel = filepath.ToSlash(r)
			}
		}
		f := normalizer.Finding{
			ID:          "trojan-" + shortHash(d.Rule+"|"+d.Sink.Key),
			Scanner:     "trojan",
			Category:    "sast",
			Severity:    detectionSeverity(d.Severity),
			Title:       d.Title,
			RawMessage:  d.Message,
			FilePath:    filepath.Join(projectPath, filepath.FromSlash(rel)),
			LineNumber:  d.Sink.Line,
			CodeSnippet: sourceLines(abs, d.Sink.Line, 3),
			RuleID:      d.Rule,
			Status:      normalizer.StatusOpen,
		}
		switch d.Rule {
		case graph.DetectSQLInjection:
			f.CWEIDs = []string{"CWE-89"}
			f.OWASP = []string{"A03:2021 - Injection"}
		case graph.DetectStoredXSS:
			f.CWEIDs = []string{"CWE-79"}
			f.OWASP = []string{"A03:2021 - Injection"}
		}
		out = append(out, f)
	}
	return out
}

func detectionSeverity(s string) normalizer.Severity {
	switch s {
	case "critical":
		return normalizer.SeverityCritical
	case "high":
		return normalizer.SeverityHigh
	case "medium":
		return normalizer.SeverityMedium
	default:
		return normalizer.SeverityLow
	}
}

func shortHash(s string) string {
	h := sha256.Sum256([]byte(s))
	return fmt.Sprintf("%x", h)[:12]
}

// sourceLines returns up to n lines of file starting at line (1-based),
// each trimmed, joined by newlines; "" when unreadable.
func sourceLines(file string, line, n int) string {
	src, err := os.ReadFile(file)
	if err != nil || line <= 0 {
		return ""
	}
	lines := strings.Split(string(src), "\n")
	if line > len(lines) {
		return ""
	}
	end := line - 1 + n
	if end > len(lines) {
		end = len(lines)
	}
	var out []string
	for _, l := range lines[line-1 : end] {
		if t := strings.TrimSpace(l); t != "" {
			out = append(out, t)
		}
	}
	return strings.Join(out, "\n")
}
