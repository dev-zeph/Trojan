// Package routes resolves a live URL back to the source handler that serves it,
// plus the guard chain (auth middleware/decorators) protecting it. This is the
// grey-box link (docs/trojan-agentic-implementation.md §7): the DAST agent sees
// URLs; the resolver tells it which code to read so it can form source-grounded
// hypotheses instead of blindly fuzzing.
//
// Two halves: extraction (source tree -> []Route, framework-specific) and
// matching (live URL -> best Route, framework-agnostic — this file). All pure Go,
// no CGO.
package routes

import (
	"sort"
	"strings"
)

// Route is the canonical, framework-independent description of one endpoint, so
// matching is uniform regardless of how the route was extracted (§7.2).
type Route struct {
	Method        string   // "GET"/"POST"/… uppercase, or "" = any method
	PathPattern   string   // canonical: /api/users/{id}, catch-all /files/{path...}
	ParamNames    []string // e.g. ["id"]
	HandlerFile   string   // source file that handles this route
	HandlerLine   int      // 1-indexed; 0 if unknown
	HandlerSymbol string   // handler function/export name when known
	Guards        []string // middleware/decorators in the applied chain (auth etc.)
	Framework     string   // "nextjs", "express", …
	Confidence    float64  // 1.0 filesystem/declarative; lower for regex/semantic
	Source        string   // "filesystem" | "static" | "semantic" | "llm"
}

// segKind classifies one pattern segment.
type segKind int

const (
	segLiteral segKind = iota
	segParam            // {name} — exactly one URL segment
	segCatchAll         // {name...} — one or more remaining segments
	segOptCatchAll      // {name...?} — zero or more remaining segments
)

type patSeg struct {
	kind segKind
	text string // literal text (segLiteral only)
}

// Match returns the best route for a request, if any. A route matches when the
// method agrees (route.Method == "" means any) and the path fits its pattern.
// When several match, the most specific wins: most literal segments first, then
// non-catch-all over catch-all, then higher Confidence — so /api/users/me beats
// /api/users/{id}, and an exact route beats a wildcard.
func Match(rs []Route, method, urlPath string) (Route, bool) {
	reqSegs := splitPath(urlPath)
	method = strings.ToUpper(method)

	type cand struct {
		route    Route
		literals int
		catchAll bool
	}
	var cands []cand
	for _, r := range rs {
		if r.Method != "" && !strings.EqualFold(r.Method, method) {
			continue
		}
		pat := parsePattern(r.PathPattern)
		ok, literals, catchAll := matchSegs(pat, reqSegs)
		if !ok {
			continue
		}
		cands = append(cands, cand{route: r, literals: literals, catchAll: catchAll})
	}
	if len(cands) == 0 {
		return Route{}, false
	}
	sort.SliceStable(cands, func(i, j int) bool {
		if cands[i].literals != cands[j].literals {
			return cands[i].literals > cands[j].literals // more literals = more specific
		}
		if cands[i].catchAll != cands[j].catchAll {
			return !cands[i].catchAll // prefer non-catch-all
		}
		return cands[i].route.Confidence > cands[j].route.Confidence
	})
	return cands[0].route, true
}

// matchSegs reports whether the pattern matches the URL segments, and returns the
// number of literal segments matched and whether a catch-all was used (for
// specificity ranking).
func matchSegs(pat []patSeg, url []string) (ok bool, literals int, catchAll bool) {
	for i, p := range pat {
		switch p.kind {
		case segCatchAll:
			// Must be the last pattern segment; consumes >=1 remaining segments.
			return len(url) >= i+1, literals, true
		case segOptCatchAll:
			// Consumes zero or more remaining segments.
			return true, literals, true
		default:
			if i >= len(url) {
				return false, 0, false
			}
			if p.kind == segLiteral {
				if p.text != url[i] {
					return false, 0, false
				}
				literals++
			}
			// segParam matches any single segment.
		}
	}
	// No catch-all consumed the tail: lengths must be equal.
	return len(pat) == len(url), literals, false
}

// parsePattern splits a canonical pattern into typed segments. Unlike splitPath
// it does not strip at "?", since the optional-catch-all syntax {name...?}
// legitimately contains one.
func parsePattern(pattern string) []patSeg {
	pattern = strings.Trim(pattern, "/")
	var raw []string
	if pattern != "" {
		raw = strings.Split(pattern, "/")
	}
	segs := make([]patSeg, len(raw))
	for i, s := range raw {
		switch {
		case strings.HasPrefix(s, "{") && strings.HasSuffix(s, "}"):
			inner := s[1 : len(s)-1]
			switch {
			case strings.HasSuffix(inner, "...?"):
				segs[i] = patSeg{kind: segOptCatchAll}
			case strings.HasSuffix(inner, "..."):
				segs[i] = patSeg{kind: segCatchAll}
			default:
				segs[i] = patSeg{kind: segParam}
			}
		default:
			segs[i] = patSeg{kind: segLiteral, text: s}
		}
	}
	return segs
}

// splitPath normalizes a path (drops query, fragment, and empty segments) and
// splits it into segments. Root "/" yields an empty slice.
func splitPath(p string) []string {
	if i := strings.IndexAny(p, "?#"); i >= 0 {
		p = p[:i]
	}
	p = strings.Trim(p, "/")
	if p == "" {
		return nil
	}
	return strings.Split(p, "/")
}
