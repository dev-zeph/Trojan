package reach

import (
	"path"
	"regexp"
	"strings"

	"github.com/dev-zeph/trojan/internal/graph"
)

var (
	// expressRoute matches the symbol the JS builder gives Express handlers:
	// "POST /api/notes".
	expressRoute = regexp.MustCompile(`^[A-Z]+ /`)
	httpMethods  = map[string]bool{"GET": true, "POST": true, "PUT": true, "PATCH": true, "DELETE": true, "HEAD": true, "OPTIONS": true}
	// pyDecorator matches Flask/FastAPI route decorators:
	// @app.post("/items") or @bp.route("/x", methods=["POST"]).
	pyDecorator = regexp.MustCompile(`^\s*@[\w.]*\.(get|post|put|patch|delete|route|api_route)\(\s*["']([^"']*)["'](.*)`)
	pyMethods   = regexp.MustCompile(`methods\s*=\s*\[\s*["'](\w+)["']`)
)

// Symbol strips the "<file base>." prefix the JS and Python builders put on
// node names ("route.ts.POST" -> "POST"). Go names ("api.Login") are kept.
func Symbol(n graph.Node) string {
	base := path.Base(strings.ReplaceAll(n.File, "\\", "/")) + "."
	return strings.TrimPrefix(n.Name, base)
}

// Label names an entrypoint the way a developer would: "POST /api/orders",
// "server action deletePost", "middleware". Falls back to the symbol.
func (a *Analyzer) Label(n graph.Node) string {
	sym := Symbol(n)
	rel := a.Rel(n.File)
	base := path.Base(rel)
	ext := path.Ext(base)
	stem := strings.TrimSuffix(base, ext)

	if expressRoute.MatchString(sym) {
		return sym
	}
	if ext == ".py" {
		if r := a.pyRoute(n); r != "" {
			return r
		}
		return sym
	}
	if !isJS(ext) {
		return sym
	}
	if stem == "middleware" || stem == "proxy" {
		return "middleware"
	}
	if p, ok := nextRoutePath(rel); ok {
		if stem == "route" && httpMethods[sym] {
			return sym + " " + p
		}
		if strings.Contains(rel, "pages/api/") {
			return "ANY " + p
		}
	}
	if n.Source {
		return "server action " + sym
	}
	return sym
}

func isJS(ext string) bool {
	switch ext {
	case ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs":
		return true
	}
	return false
}

// nextRoutePath turns a Next.js file path into its URL path:
// app/api/orders/route.ts -> /api/orders, src/app/(shop)/[id]/route.ts ->
// /[id], pages/api/user.ts -> /api/user.
func nextRoutePath(rel string) (string, bool) {
	segs := strings.Split(rel, "/")
	for i, s := range segs {
		if s == "app" || s == "pages" {
			rest := segs[i+1:]
			if len(rest) == 0 {
				return "", false
			}
			last := rest[len(rest)-1]
			stem := strings.TrimSuffix(last, path.Ext(last))
			if s == "app" {
				rest = rest[:len(rest)-1] // drop route.ts / page.tsx
			} else if stem == "index" {
				rest = rest[:len(rest)-1]
			} else {
				rest = append(rest[:len(rest)-1], stem)
			}
			var parts []string
			for _, r := range rest {
				if strings.HasPrefix(r, "(") || strings.HasPrefix(r, "@") {
					continue // route groups and parallel slots aren't in the URL
				}
				parts = append(parts, r)
			}
			return "/" + strings.Join(parts, "/"), true
		}
	}
	return "", false
}

// pyRoute reads the decorators just above a Python function for its route.
func (a *Analyzer) pyRoute(n graph.Node) string {
	lines := a.sourceLines(n.File)
	if n.Line <= 0 || n.Line > len(lines) {
		return ""
	}
	// Start at the def line (or the decorator line the builder recorded) and
	// walk up through the decorator block.
	for i := n.Line - 1; i >= 0 && i >= n.Line-8; i-- {
		line := strings.TrimSpace(lines[i])
		if m := pyDecorator.FindStringSubmatch(lines[i]); m != nil {
			method := strings.ToUpper(m[1])
			if method == "ROUTE" || method == "API_ROUTE" {
				method = "GET"
				if mm := pyMethods.FindStringSubmatch(m[3]); mm != nil {
					method = strings.ToUpper(mm[1])
				}
			}
			return method + " " + m[2]
		}
		if i < n.Line-1 && line != "" && !strings.HasPrefix(line, "@") {
			break // left the decorator block
		}
	}
	return ""
}
