package orgcontext

import (
	"path/filepath"
	"regexp"
	"strings"

	"github.com/dev-zeph/trojan/internal/graph"
)

// Tag keys ApplyOverlay writes into graph.Node.Tags.
const (
	// TagSensitiveCategory holds a comma-joined list of SensitiveDataCategory
	// names a node matched (e.g. "PII" or "PII,payment").
	TagSensitiveCategory = "sensitive_data_category"
	// TagBoundary holds a comma-joined list of TrustBoundary names a node
	// falls inside (usually just one).
	TagBoundary = "trust_boundary"
)

// OverlayResult summarizes what ApplyOverlay changed, so a caller can report
// it (e.g. "org context marked 4 nodes as PHI, tagged 2 trust boundaries").
type OverlayResult struct {
	// SensitiveMatches counts (node, category) matches, not unique nodes: a
	// node matching two categories counts twice.
	SensitiveMatches int
	// BoundaryMatches counts (node, boundary) matches, not unique nodes.
	BoundaryMatches int
}

// ApplyOverlay annotates a built graph.Graph in place using the authored
// patterns in ctx: nodes matching a sensitive_data pattern are marked PII
// (adding to, never clearing, whatever the generic heuristic already set) and
// tagged with the category name; nodes matching a trust_boundaries pattern
// are tagged with that boundary's name. This makes the graph reflect the
// organization's own stated model of the system, layered on top of the
// generic heuristics graph.BuildFromGoFiles already applied.
//
// ApplyOverlay is idempotent to call more than once (tags dedupe), and safe
// to call with a nil or empty ctx (a no-op).
func ApplyOverlay(g *graph.Graph, ctx *OrgContext) OverlayResult {
	var res OverlayResult
	if g == nil || ctx == nil {
		return res
	}

	sensitive := compileSensitive(ctx.SensitiveData)
	boundaries := compileBoundaries(ctx.TrustBoundaries)

	for i := range g.Nodes {
		n := &g.Nodes[i]

		for _, sd := range sensitive {
			if sd.pattern.matches(n) {
				n.PII = true
				if setTag(n, TagSensitiveCategory, sd.category) {
					res.SensitiveMatches++
				}
			}
		}

		for _, tb := range boundaries {
			if tb.pattern.matches(n) {
				if setTag(n, TagBoundary, tb.name) {
					res.BoundaryMatches++
				}
			}
		}
	}

	return res
}

// setTag adds value to the comma-joined tag at key, creating the Tags map if
// needed. It reports whether value was newly added (false if already present,
// so callers can count unique matches).
func setTag(n *graph.Node, key, value string) bool {
	if value == "" {
		return false
	}
	if n.Tags == nil {
		n.Tags = make(map[string]string)
	}
	existing, ok := n.Tags[key]
	if !ok {
		n.Tags[key] = value
		return true
	}
	for _, part := range strings.Split(existing, ",") {
		if part == value {
			return false
		}
	}
	n.Tags[key] = existing + "," + value
	return true
}

// pattern is a file-glob and/or symbol-regexp matcher shared by sensitive
// data categories and trust boundaries. A node matches if it hits either
// list; an empty pattern (no globs, no regexes) never matches.
type pattern struct {
	fileGlobs   []*regexp.Regexp
	symbolRegex []*regexp.Regexp
}

func (p pattern) matches(n *graph.Node) bool {
	file := filepath.ToSlash(n.File)
	for _, re := range p.fileGlobs {
		if re.MatchString(file) {
			return true
		}
	}
	for _, re := range p.symbolRegex {
		if re.MatchString(n.Name) {
			return true
		}
	}
	return false
}

type compiledSensitive struct {
	pattern  pattern
	category string
}

type compiledBoundary struct {
	pattern pattern
	name    string
}

func compileSensitive(defs []SensitiveDataCategory) []compiledSensitive {
	out := make([]compiledSensitive, 0, len(defs))
	for _, d := range defs {
		out = append(out, compiledSensitive{
			pattern:  compilePattern(d.FilePatterns, d.SymbolPatterns),
			category: d.Category,
		})
	}
	return out
}

func compileBoundaries(defs []TrustBoundary) []compiledBoundary {
	out := make([]compiledBoundary, 0, len(defs))
	for _, d := range defs {
		out = append(out, compiledBoundary{
			pattern: compilePattern(d.FilePatterns, d.SymbolPatterns),
			name:    d.Name,
		})
	}
	return out
}

// compilePattern compiles authored file globs and symbol regexes. Patterns
// that fail to compile are skipped rather than aborting the whole overlay
// (one typo in context.yaml should not disable every other rule).
func compilePattern(fileGlobs, symbolPatterns []string) pattern {
	var p pattern
	for _, g := range fileGlobs {
		if re, err := regexp.Compile(globToRegexp(g)); err == nil {
			p.fileGlobs = append(p.fileGlobs, re)
		}
	}
	for _, s := range symbolPatterns {
		if re, err := regexp.Compile("(?i)" + s); err == nil {
			p.symbolRegex = append(p.symbolRegex, re)
		}
	}
	return p
}

// globToRegexp turns a simple, authored path glob ("internal/billing/**",
// "*_test.go") into an unanchored, case-insensitive regexp: "**" matches
// across path separators, "*" matches within a single path segment. It is
// intentionally unanchored (a substring match) because graph.Node.File may be
// absolute or relative depending on how the graph was built, and the user
// authoring context.yaml only knows the project-relative shape of the path.
func globToRegexp(glob string) string {
	glob = filepath.ToSlash(glob)
	var b strings.Builder
	b.WriteString("(?i)")
	for i := 0; i < len(glob); {
		switch {
		case strings.HasPrefix(glob[i:], "**"):
			b.WriteString(".*")
			i += 2
		case glob[i] == '*':
			b.WriteString("[^/]*")
			i++
		default:
			b.WriteString(regexp.QuoteMeta(string(glob[i])))
			i++
		}
	}
	return b.String()
}
