package routes

import (
	"os"
	"regexp"
	"strings"
)

var (
	// @app.route("/x", methods=["GET", "POST"]) / @bp.route('/y')
	flaskRouteRe      = regexp.MustCompile(`@(\w+)\.route\s*\(\s*['"]([^'"]*)['"]`)
	flaskRouteStartRe = regexp.MustCompile(`^\s*@\w+\.route\s*\(`)
	// methods=["GET", "POST"] (anywhere in the decorator's argument list)
	flaskMethodsRe = regexp.MustCompile(`methods\s*=\s*[\[(]([^\])]*)[\])]`)
	flaskMethodRe  = regexp.MustCompile(`['"](\w+)['"]`)
	// bp = Blueprint("admin", __name__, url_prefix="/admin")
	flaskBlueprintRe = regexp.MustCompile(`(\w+)\s*=\s*Blueprint\s*\(([^)]*)\)`)
	// app.register_blueprint(bp, url_prefix="/api")
	flaskRegisterRe  = regexp.MustCompile(`register_blueprint\s*\(\s*(?:\w+\.)?(\w+)([^)]*)\)`)
	flaskPrefixArgRe = regexp.MustCompile(`url_prefix\s*=\s*['"]([^'"]*)['"]`)
	// <int:cid>, <path:p>, <name>
	flaskParamRe = regexp.MustCompile(`<(?:(\w+):)?(\w+)>`)
	// @login_required / @auth.login_required() / @roles_required("admin")
	pyDecoratorRe = regexp.MustCompile(`^\s*@([\w.]+)`)
)

// extractFlask scans Python files for Flask route decorators (@x.route and the
// Flask 2 @x.get/@x.post shorthands). Regex-based (confidence 0.7). Blueprint
// url_prefix values are collected project-wide by variable name, so a
// blueprint declared in one file and registered in another still gets its
// prefix; two blueprints sharing a variable name in different files is an
// honest limit. Decorators stacked under the route (e.g. @login_required) are
// recorded as Guards so the agent can see which handlers have no auth check.
func extractFlask(projectPath string) []Route {
	files := walkFiles(projectPath, pyExts)
	contents := make(map[string]string, len(files))
	prefix := map[string]string{}
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			continue
		}
		c := string(data)
		contents[file] = c
		for _, m := range flaskBlueprintRe.FindAllStringSubmatch(c, -1) {
			if p := flaskPrefixArgRe.FindStringSubmatch(m[2]); p != nil {
				prefix[m[1]] = p[1]
			}
		}
	}
	// register_blueprint(url_prefix=) overrides the Blueprint's own prefix.
	for _, c := range contents {
		for _, m := range flaskRegisterRe.FindAllStringSubmatch(c, -1) {
			if p := flaskPrefixArgRe.FindStringSubmatch(m[2]); p != nil {
				prefix[m[1]] = p[1]
			}
		}
	}

	var routes []Route
	for _, file := range files {
		c, ok := contents[file]
		if !ok {
			continue
		}
		routes = append(routes, flaskRoutesInFile(relOrBase(projectPath, file), c, prefix)...)
	}
	return routes
}

func flaskRoutesInFile(relFile, content string, prefix map[string]string) []Route {
	lines := strings.Split(content, "\n")
	var routes []Route
	for i, line := range lines {
		var recv, path string
		var methods []string
		switch {
		case flaskRouteStartRe.MatchString(line):
			// The path may sit on the line after "@app.route(", so match the
			// whole (possibly wrapped) decorator.
			args := decoratorArgs(lines, i)
			m := flaskRouteRe.FindStringSubmatch(args)
			if m == nil {
				continue
			}
			recv, path, methods = m[1], m[2], flaskMethods(args)
		default:
			m := fastapiDecoratorRe.FindStringSubmatch(line) // Flask 2 @app.get(...)
			if m == nil {
				continue
			}
			recv, path, methods = m[1], m[3], []string{strings.ToUpper(m[2])}
		}
		if p, ok := prefix[recv]; ok {
			path = joinPath(p, path)
		} else if !strings.HasPrefix(path, "/") {
			path = "/" + path
		}
		pattern := flaskCanonPath(path)
		symbol, guards := flaskHandler(lines, i+1)
		for _, method := range methods {
			r := Route{
				Method:        method,
				PathPattern:   pattern,
				HandlerFile:   relFile,
				HandlerLine:   i + 1,
				HandlerSymbol: symbol,
				Guards:        guards,
				Framework:     string(FrameworkFlask),
				Confidence:    0.7,
				Source:        "static",
			}
			r.ParamNames = paramNamesOf(pattern)
			routes = append(routes, r)
		}
	}
	return routes
}

// decoratorArgs returns the decorator's argument text starting at line i,
// following it onto later lines until the parentheses balance (methods=[...]
// is often wrapped onto its own line).
func decoratorArgs(lines []string, i int) string {
	var b strings.Builder
	depth := 0
	for j := i; j < len(lines) && j < i+6; j++ {
		b.WriteString(lines[j])
		b.WriteByte(' ')
		depth += strings.Count(lines[j], "(") - strings.Count(lines[j], ")")
		if depth <= 0 {
			break
		}
	}
	return b.String()
}

// flaskMethods reads methods=[...] from a route decorator; Flask's default is GET.
func flaskMethods(args string) []string {
	m := flaskMethodsRe.FindStringSubmatch(args)
	if m == nil {
		return []string{"GET"}
	}
	var out []string
	for _, mm := range flaskMethodRe.FindAllStringSubmatch(m[1], -1) {
		out = append(out, strings.ToUpper(mm[1]))
	}
	if len(out) == 0 {
		return []string{"GET"}
	}
	return out
}

// flaskCanonPath converts Flask converters to canonical params: <int:id> and
// <id> become {id}; <path:p> becomes the catch-all {p...}.
func flaskCanonPath(p string) string {
	return flaskParamRe.ReplaceAllStringFunc(p, func(s string) string {
		m := flaskParamRe.FindStringSubmatch(s)
		if m[1] == "path" {
			return "{" + m[2] + "...}"
		}
		return "{" + m[2] + "}"
	})
}

// flaskHandler walks the decorator stack below a route decorator to the def,
// returning the handler name and the non-route decorators (guards) in order.
func flaskHandler(lines []string, from int) (symbol string, guards []string) {
	for i := from; i < len(lines) && i < from+12; i++ {
		trimmed := strings.TrimSpace(lines[i])
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if m := pyDecoratorRe.FindStringSubmatch(lines[i]); m != nil {
			name := m[1]
			last := name[strings.LastIndex(name, ".")+1:]
			if last == "route" || isHTTPVerb(last) {
				continue // another route decorator stacked on the same handler
			}
			guards = append(guards, name)
			continue
		}
		if strings.HasPrefix(trimmed, "@") || strings.HasPrefix(trimmed, ")") || strings.HasPrefix(trimmed, "]") ||
			strings.HasPrefix(trimmed, "methods") || strings.HasPrefix(trimmed, "'") || strings.HasPrefix(trimmed, `"`) {
			continue // continuation of a wrapped decorator
		}
		if m := pyDefRe.FindStringSubmatch(lines[i]); m != nil {
			return m[1], guards
		}
		return "", guards
	}
	return "", guards
}

func isHTTPVerb(s string) bool {
	switch strings.ToLower(s) {
	case "get", "post", "put", "patch", "delete", "head", "options", "trace":
		return true
	}
	return false
}
