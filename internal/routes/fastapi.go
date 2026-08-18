package routes

import (
	"os"
	"regexp"
	"strings"
)

var pyExts = map[string]bool{".py": true}

var (
	// @app.get("/x") / @router.post('/y')
	fastapiDecoratorRe = regexp.MustCompile(`@(\w+)\.(get|post|put|patch|delete|head|options|trace)\s*\(\s*['"]([^'"]*)['"]`)
	// router = APIRouter(prefix="/users")
	fastapiRouterPrefixRe = regexp.MustCompile(`(\w+)\s*=\s*APIRouter\s*\([^)]*prefix\s*=\s*['"]([^'"]*)['"]`)
	// app.include_router(router, prefix="/api")
	fastapiIncludeRe = regexp.MustCompile(`include_router\s*\(\s*(\w+)[^)]*?prefix\s*=\s*['"]([^'"]*)['"]`)
	// def handler( / async def handler(
	pyDefRe = regexp.MustCompile(`^\s*(?:async\s+)?def\s+(\w+)`)
)

// extractFastAPI scans Python files for FastAPI route decorators. Regex-based
// (confidence 0.7). Prefixes from APIRouter(prefix=) and include_router(prefix=)
// are resolved within a file; cross-file router wiring is an honest limit (§7.4).
func extractFastAPI(projectPath string) []Route {
	var routes []Route
	for _, file := range walkFiles(projectPath, pyExts) {
		content, err := os.ReadFile(file)
		if err != nil {
			continue
		}
		routes = append(routes, fastapiRoutesInFile(relOrBase(projectPath, file), string(content))...)
	}
	return routes
}

func fastapiRoutesInFile(relFile, content string) []Route {
	lines := strings.Split(content, "\n")

	// receiver var -> combined prefix (include_router prefix + APIRouter prefix).
	prefix := map[string]string{}
	for _, m := range fastapiRouterPrefixRe.FindAllStringSubmatch(content, -1) {
		prefix[m[1]] = m[2]
	}
	for _, m := range fastapiIncludeRe.FindAllStringSubmatch(content, -1) {
		prefix[m[1]] = joinPath(m[2], prefix[m[1]]) // include prefix is outer
	}

	var routes []Route
	for i, line := range lines {
		m := fastapiDecoratorRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		recv, method, path := m[1], strings.ToUpper(m[2]), m[3]
		if p, ok := prefix[recv]; ok {
			path = joinPath(p, path)
		} else if !strings.HasPrefix(path, "/") {
			path = "/" + path
		}
		r := Route{
			Method:        method,
			PathPattern:   fastapiCanonPath(path),
			HandlerFile:   relFile,
			HandlerLine:   i + 1,
			HandlerSymbol: lookaheadDef(lines, i+1),
			Framework:     string(FrameworkFastAPI),
			Confidence:    0.7,
			Source:        "static",
		}
		r.ParamNames = paramNamesOf(r.PathPattern)
		routes = append(routes, r)
	}
	return routes
}

// fastapiCanonPath converts FastAPI path params to canonical form. {id} already
// matches; {name:path} (catch-all converter) becomes {name...}; other converters
// ({id:int}) collapse to {id}.
func fastapiCanonPath(p string) string {
	segs := strings.Split(p, "/")
	for i, s := range segs {
		if !strings.HasPrefix(s, "{") || !strings.HasSuffix(s, "}") {
			continue
		}
		inner := s[1 : len(s)-1]
		name, conv, hasConv := strings.Cut(inner, ":")
		switch {
		case hasConv && conv == "path":
			segs[i] = "{" + name + "...}"
		default:
			segs[i] = "{" + name + "}"
		}
	}
	return strings.Join(segs, "/")
}

// lookaheadDef finds the handler function name on the first `def` line at or
// after `from`, skipping stacked decorators/blank lines.
func lookaheadDef(lines []string, from int) string {
	for i := from; i < len(lines) && i < from+5; i++ {
		trimmed := strings.TrimSpace(lines[i])
		if trimmed == "" || strings.HasPrefix(trimmed, "@") {
			continue
		}
		if m := pyDefRe.FindStringSubmatch(lines[i]); m != nil {
			return m[1]
		}
		return "" // first non-decorator line wasn't a def
	}
	return ""
}
