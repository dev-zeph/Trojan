package routes

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var jsExts = map[string]bool{".js": true, ".ts": true, ".mjs": true, ".cjs": true, ".jsx": true, ".tsx": true}

var (
	// app.get('/x', h) / router.post("/y", h) / api.all(`/z`, h)
	expressRouteRe = regexp.MustCompile("\\b(\\w+)\\.(get|post|put|patch|delete|all|head|options)\\s*\\(\\s*['\"`]([^'\"`]*)['\"`]")
	// app.use('/api', router)
	expressMountRe = regexp.MustCompile("\\b(\\w+)\\.use\\s*\\(\\s*['\"`]([^'\"`]+)['\"`]\\s*,\\s*(\\w+)")
	// trailing bare-identifier handler: , handlerName)
	expressHandlerRe = regexp.MustCompile(`,\s*(\w+)\s*\)\s*;?\s*$`)
)

// extractExpress scans JS/TS files for Express route registrations. Regex-based
// (no CGO parser — §1), so confidence is 0.7, not filesystem-1.0. Mount prefixes
// (app.use('/api', router)) are resolved within a single file; cross-file mounts
// are an honest limit (§7.4) — such routes keep their local path.
func extractExpress(projectPath string) []Route {
	var routes []Route
	for _, file := range walkFiles(projectPath, jsExts) {
		content, err := os.ReadFile(file)
		if err != nil {
			continue
		}
		rel := relOrBase(projectPath, file)
		routes = append(routes, expressRoutesInFile(rel, string(content))...)
	}
	return routes
}

func expressRoutesInFile(relFile, content string) []Route {
	// Map router variable -> mount prefix (same-file resolution).
	mounts := map[string]string{}
	for _, m := range expressMountRe.FindAllStringSubmatch(content, -1) {
		mounts[m[3]] = m[2] // mountedVar -> prefix
	}

	var routes []Route
	for lineNo, line := range strings.Split(content, "\n") {
		for _, m := range expressRouteRe.FindAllStringSubmatch(line, -1) {
			recv, method, path := m[1], strings.ToUpper(m[2]), m[3]
			if prefix, ok := mounts[recv]; ok {
				path = joinPath(prefix, path)
			} else if !strings.HasPrefix(path, "/") {
				path = "/" + path
			}
			if method == "ALL" {
				method = "" // any method
			}
			r := Route{
				Method:      method,
				PathPattern: expressCanonPath(path),
				HandlerFile: relFile,
				HandlerLine: lineNo + 1,
				Framework:   string(FrameworkExpress),
				Confidence:  0.7,
				Source:      "static",
			}
			if h := expressHandlerRe.FindStringSubmatch(line); h != nil {
				r.HandlerSymbol = h[1]
			}
			r.ParamNames = paramNamesOf(r.PathPattern)
			routes = append(routes, r)
		}
	}
	return routes
}

// expressCanonPath converts Express path syntax to the canonical form:
// :id -> {id}, a bare * segment -> catch-all.
func expressCanonPath(p string) string {
	segs := strings.Split(p, "/")
	for i, s := range segs {
		switch {
		case s == "*":
			segs[i] = "{wildcard...}"
		case strings.HasPrefix(s, ":"):
			name := strings.TrimSuffix(strings.TrimPrefix(s, ":"), "?")
			segs[i] = "{" + name + "}"
		}
	}
	return strings.Join(segs, "/")
}

// paramNamesOf extracts the {name} param names from a canonical pattern.
func paramNamesOf(pattern string) []string {
	var names []string
	for tok := range strings.SplitSeq(strings.Trim(pattern, "/"), "/") {
		if strings.HasPrefix(tok, "{") && strings.HasSuffix(tok, "}") {
			inner := strings.TrimSuffix(strings.TrimSuffix(strings.Trim(tok, "{}"), "...?"), "...")
			if inner != "" {
				names = append(names, inner)
			}
		}
	}
	return names
}

// relOrBase returns file relative to root, or its base name on failure.
func relOrBase(root, file string) string {
	if rel, err := filepath.Rel(root, file); err == nil {
		return filepath.ToSlash(rel)
	}
	return filepath.Base(file)
}
