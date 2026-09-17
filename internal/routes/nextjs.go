package routes

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// extractNextjs builds routes from a Next.js project's filesystem — the most
// precise extractor (no code parsing needed for the path; §7.1 "filesystem-
// routed"). Handles both the App Router (app/) and the Pages Router (pages/),
// under the project root or src/, and attaches the middleware guard chain.
func extractNextjs(projectPath string) []Route {
	var routes []Route

	appDir, appBase := firstExisting(projectPath, "app", filepath.Join("src", "app"))
	if appDir != "" {
		routes = append(routes, extractAppRouter(appDir, appBase)...)
	}
	pagesDir, pagesBase := firstExisting(projectPath, "pages", filepath.Join("src", "pages"))
	if pagesDir != "" {
		routes = append(routes, extractPagesRouter(pagesDir, pagesBase)...)
	}

	applyMiddlewareGuards(projectPath, routes)
	return routes
}

var (
	// export function GET / export async function POST / export const DELETE =
	methodFuncRe  = regexp.MustCompile(`export\s+(?:async\s+)?function\s+(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\b`)
	methodConstRe = regexp.MustCompile(`export\s+const\s+(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s*=`)
	routeFileRe   = regexp.MustCompile(`^route\.(ts|js|tsx|jsx)$`)
	pageFileRe    = regexp.MustCompile(`^page\.(tsx|jsx|ts|js)$`)
)

// extractAppRouter walks an app/ directory. route.* files define API endpoints
// (methods = their exported HTTP functions); page.* files are GET endpoints.
func extractAppRouter(appDir, relBase string) []Route {
	var routes []Route
	filepath.WalkDir(appDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		name := d.Name()
		isRoute := routeFileRe.MatchString(name)
		isPage := pageFileRe.MatchString(name)
		if !isRoute && !isPage {
			return nil
		}
		relDir := dirRelTo(appDir, path)
		urlPath, params, routable := nextURLPath(relDir)
		if !routable {
			return nil
		}
		if isRoute {
			content, _ := os.ReadFile(path)
			for _, m := range routeMethods(string(content)) {
				routes = append(routes, Route{
					Method:        m.method,
					PathPattern:   urlPath,
					ParamNames:    params,
					HandlerFile:   filepath.Join(relBase, relDir, name),
					HandlerLine:   m.line,
					HandlerSymbol: m.method,
					Framework:     string(FrameworkNextjs),
					Confidence:    1.0,
					Source:        "filesystem",
				})
			}
		} else { // page
			routes = append(routes, Route{
				Method:        "GET",
				PathPattern:   urlPath,
				ParamNames:    params,
				HandlerFile:   filepath.Join(relBase, relDir, name),
				HandlerSymbol: "default",
				Framework:     string(FrameworkNextjs),
				Confidence:    1.0,
				Source:        "filesystem",
			})
		}
		return nil
	})
	return routes
}

// extractPagesRouter walks a pages/ directory. Each file is an endpoint; the URL
// is the file path minus its extension (index -> parent). API routes handle any
// method (single default handler), pages are GET.
func extractPagesRouter(pagesDir, relBase string) []Route {
	var routes []Route
	filepath.WalkDir(pagesDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		ext := filepath.Ext(path)
		switch ext {
		case ".ts", ".tsx", ".js", ".jsx":
		default:
			return nil
		}
		base := strings.TrimSuffix(d.Name(), ext)
		if strings.HasPrefix(base, "_") { // _app, _document, _error — not routes
			return nil
		}
		relDir := dirRelTo(pagesDir, path)
		// The filename (minus index) is the last path segment.
		segDir := relDir
		if base != "index" {
			segDir = filepath.Join(relDir, base)
		}
		urlPath, params, routable := nextURLPath(segDir)
		if !routable {
			return nil
		}
		isAPI := strings.HasPrefix(filepath.ToSlash(urlPath), "/api")
		method := "GET"
		if isAPI {
			method = "" // default handler serves any method
		}
		routes = append(routes, Route{
			Method:        method,
			PathPattern:   urlPath,
			ParamNames:    params,
			HandlerFile:   filepath.Join(relBase, relDir, d.Name()),
			HandlerSymbol: "default",
			Framework:     string(FrameworkNextjs),
			Confidence:    1.0,
			Source:        "filesystem",
		})
		return nil
	})
	return routes
}

type methodAt struct {
	method string
	line   int
}

// routeMethods finds the HTTP methods a route.ts exports, with line numbers.
func routeMethods(content string) []methodAt {
	seen := map[string]int{}
	for i, line := range strings.Split(content, "\n") {
		for _, re := range []*regexp.Regexp{methodFuncRe, methodConstRe} {
			if m := re.FindStringSubmatch(line); m != nil {
				if _, ok := seen[m[1]]; !ok {
					seen[m[1]] = i + 1
				}
			}
		}
	}
	// Deterministic order.
	var out []methodAt
	for _, m := range []string{"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"} {
		if ln, ok := seen[m]; ok {
			out = append(out, methodAt{method: m, line: ln})
		}
	}
	return out
}

// nextURLPath converts a Next.js route directory (relative to app/pages root)
// into a canonical URL pattern. Route groups (x) and parallel slots @x are
// dropped from the path; a private folder _x makes the whole route non-routable.
func nextURLPath(relDir string) (pattern string, params []string, routable bool) {
	if relDir == "." || relDir == "" {
		return "/", nil, true
	}
	var out []string
	for seg := range strings.SplitSeq(filepath.ToSlash(relDir), "/") {
		switch {
		case seg == "":
			continue
		case strings.HasPrefix(seg, "_"): // private folder — not routable
			return "", nil, false
		case strings.HasPrefix(seg, "(") && strings.HasSuffix(seg, ")"): // route group
			continue
		case strings.HasPrefix(seg, "@"): // parallel route slot
			continue
		case strings.HasPrefix(seg, "[[...") && strings.HasSuffix(seg, "]]"):
			name := strings.TrimSuffix(strings.TrimPrefix(seg, "[[..."), "]]")
			params = append(params, name)
			out = append(out, "{"+name+"...?}")
		case strings.HasPrefix(seg, "[...") && strings.HasSuffix(seg, "]"):
			name := strings.TrimSuffix(strings.TrimPrefix(seg, "[..."), "]")
			params = append(params, name)
			out = append(out, "{"+name+"...}")
		case strings.HasPrefix(seg, "[") && strings.HasSuffix(seg, "]"):
			name := strings.TrimSuffix(strings.TrimPrefix(seg, "["), "]")
			params = append(params, name)
			out = append(out, "{"+name+"}")
		default:
			out = append(out, seg)
		}
	}
	if len(out) == 0 {
		return "/", params, true
	}
	return "/" + strings.Join(out, "/"), params, true
}

// matcherRe pulls the matcher config out of a Next.js middleware file:
//
//	export const config = { matcher: ['/dashboard/:path*', '/api/:path*'] }
var (
	matcherBlockRe = regexp.MustCompile(`matcher\s*:\s*(\[[^\]]*\]|['"` + "`" + `][^'"` + "`" + `]*['"` + "`" + `])`)
	matcherStrRe   = regexp.MustCompile(`['"` + "`" + `]([^'"` + "`" + `]+)['"` + "`" + `]`)
)

// applyMiddlewareGuards finds a Next.js middleware file and records it as a guard
// on the routes it covers. Next.js middleware is the primary auth chokepoint, so
// "which routes does middleware protect?" is exactly the guard-chain question
// §7.3 flags as make-or-break. Scoping is best-effort: if the middleware declares
// a config.matcher, only routes under a matcher prefix get the guard; with no
// matcher, Next runs middleware on every route, so all routes get it.
func applyMiddlewareGuards(projectPath string, routes []Route) {
	mwPath := ""
	for _, cand := range []string{"middleware.ts", "middleware.js", filepath.Join("src", "middleware.ts"), filepath.Join("src", "middleware.js")} {
		p := filepath.Join(projectPath, cand)
		if _, err := os.Stat(p); err == nil {
			mwPath = p
			break
		}
	}
	if mwPath == "" {
		return
	}
	content, _ := os.ReadFile(mwPath)
	prefixes := middlewareMatcherPrefixes(string(content))
	guard := "middleware"

	for i := range routes {
		if len(prefixes) == 0 || pathHasAnyPrefix(routes[i].PathPattern, prefixes) {
			routes[i].Guards = append(routes[i].Guards, guard)
		}
	}
}

// middlewareMatcherPrefixes extracts literal path prefixes from a middleware
// config.matcher. A matcher like '/dashboard/:path*' yields prefix '/dashboard'.
// Returns nil when there's no matcher (middleware then applies to all routes).
func middlewareMatcherPrefixes(content string) []string {
	block := matcherBlockRe.FindStringSubmatch(content)
	if block == nil {
		return nil
	}
	var prefixes []string
	for _, m := range matcherStrRe.FindAllStringSubmatch(block[1], -1) {
		prefixes = append(prefixes, matcherLiteralPrefix(m[1]))
	}
	return prefixes
}

// matcherLiteralPrefix reduces a Next matcher pattern to its leading literal path
// (up to the first dynamic/param/glob token).
func matcherLiteralPrefix(pattern string) string {
	// Cut at the first path-to-regexp-ish token.
	if i := strings.IndexAny(pattern, ":*?(["); i >= 0 {
		pattern = pattern[:i]
	}
	return "/" + strings.Trim(pattern, "/")
}

// pathHasAnyPrefix reports whether routePath falls under one of the prefixes.
func pathHasAnyPrefix(routePath string, prefixes []string) bool {
	for _, p := range prefixes {
		if p == "/" || routePath == p || strings.HasPrefix(routePath, strings.TrimSuffix(p, "/")+"/") {
			return true
		}
	}
	return false
}

// firstExisting returns the first of the candidate subdirectories that exists
// under root, as (absolute path, relative base). Empty if none.
func firstExisting(root string, candidates ...string) (abs, rel string) {
	for _, c := range candidates {
		p := filepath.Join(root, c)
		if fi, err := os.Stat(p); err == nil && fi.IsDir() {
			return p, c
		}
	}
	return "", ""
}

// dirRelTo returns the directory of file `path` relative to `base`.
func dirRelTo(base, path string) string {
	rel, err := filepath.Rel(base, filepath.Dir(path))
	if err != nil {
		return "."
	}
	return rel
}
