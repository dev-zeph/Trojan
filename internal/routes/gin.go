package routes

import (
	"os"
	"regexp"
	"strings"
)

var goExts = map[string]bool{".go": true}

var (
	// r.GET("/x", handler) / v1.POST("/y", h) / g.Any("/z", h)
	ginRouteRe = regexp.MustCompile(`\b(\w+)\.(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|Any)\s*\(\s*"([^"]*)"`)
	// api := r.Group("/api")  (also handles = instead of :=)
	ginGroupRe = regexp.MustCompile(`(\w+)\s*:?=\s*(\w+)\.Group\s*\(\s*"([^"]*)"`)
	// trailing bare-identifier handler: , handlerName)
	ginHandlerRe = regexp.MustCompile(`,\s*([\w.]+)\s*\)\s*$`)
)

// extractGin scans Go files for Gin route registrations. Regex-based
// (confidence 0.7). Nested r.Group("/api") prefixes are resolved within a file
// by walking the group parent chain; cross-file groups are an honest limit.
func extractGin(projectPath string) []Route {
	var routes []Route
	for _, file := range walkFiles(projectPath, goExts) {
		content, err := os.ReadFile(file)
		if err != nil {
			continue
		}
		routes = append(routes, ginRoutesInFile(relOrBase(projectPath, file), string(content))...)
	}
	return routes
}

func ginRoutesInFile(relFile, content string) []Route {
	// Build the group graph: child var -> {parent var, prefix}.
	type group struct {
		parent string
		prefix string
	}
	groups := map[string]group{}
	for _, m := range ginGroupRe.FindAllStringSubmatch(content, -1) {
		groups[m[1]] = group{parent: m[2], prefix: m[3]}
	}
	// resolvePrefix walks the parent chain to build the full mount prefix.
	resolvePrefix := func(recv string) string {
		var parts []string
		seen := map[string]bool{}
		for {
			g, ok := groups[recv]
			if !ok || seen[recv] {
				break
			}
			seen[recv] = true
			parts = append([]string{strings.Trim(g.prefix, "/")}, parts...)
			recv = g.parent
		}
		return "/" + strings.Join(parts, "/")
	}

	var routes []Route
	for i, line := range strings.Split(content, "\n") {
		for _, m := range ginRouteRe.FindAllStringSubmatch(line, -1) {
			recv, method, path := m[1], strings.ToUpper(m[2]), m[3]
			path = joinPath(resolvePrefix(recv), path)
			if method == "ANY" {
				method = ""
			}
			r := Route{
				Method:      method,
				PathPattern: ginCanonPath(path),
				HandlerFile: relFile,
				HandlerLine: i + 1,
				Framework:   string(FrameworkGin),
				Confidence:  0.7,
				Source:      "static",
			}
			if h := ginHandlerRe.FindStringSubmatch(line); h != nil {
				r.HandlerSymbol = h[1]
			}
			r.ParamNames = paramNamesOf(r.PathPattern)
			routes = append(routes, r)
		}
	}
	return routes
}

// ginCanonPath converts Gin path syntax: :id -> {id}, *action -> {action...}.
func ginCanonPath(p string) string {
	segs := strings.Split(p, "/")
	for i, s := range segs {
		switch {
		case strings.HasPrefix(s, ":"):
			segs[i] = "{" + strings.TrimPrefix(s, ":") + "}"
		case strings.HasPrefix(s, "*"):
			segs[i] = "{" + strings.TrimPrefix(s, "*") + "...}"
		}
	}
	return strings.Join(segs, "/")
}
