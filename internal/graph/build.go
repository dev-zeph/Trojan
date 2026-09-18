package graph

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
)

// BuildFromGoFiles parses the given Go source files and builds the call graph
// with sinks, sources, and PII tagged. Files that fail to parse are skipped
// rather than aborting the whole build (a real repo always has some).
//
// Resolution is intentionally simple for this demo: functions are keyed by
// package-qualified name, and same-package calls (bare identifiers) form the
// internal call edges. Cross-package and method-value calls are not resolved
// into edges yet — tree-sitter + a proper symbol table close that gap in the
// production build. Sink detection, by contrast, works across packages because
// it matches the callee expression textually (exec.Command, db.Query, …).
func BuildFromGoFiles(files []string) (*Graph, error) {
	g := New()
	fset := token.NewFileSet()

	type pending struct {
		fnID    int
		callees []string // same-package callee names seen in this function body
	}
	var pends []pending

	for _, path := range files {
		src, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		file, err := parser.ParseFile(fset, path, src, 0)
		if err != nil {
			continue // partial/broken file — skip
		}
		pkg := file.Name.Name

		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			name := qualifiedName(pkg, fn)
			pos := fset.Position(fn.Pos())
			fnID := g.addNode(Node{
				Kind:   KindFunc,
				Name:   name,
				File:   pos.Filename,
				Line:   pos.Line,
				Source: isHTTPHandler(fn),
			})
			g.byFunc[name] = fnID

			p := pending{fnID: fnID}
			// Walk the body once: collect same-package callees (for edges),
			// detect sinks, and flag PII touches.
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				switch e := n.(type) {
				case *ast.CallExpr:
					if callee, ok := sameePackageCallee(e); ok {
						p.callees = append(p.callees, pkg+"."+callee)
					}
					if rule, sev, ok := matchSink(e); ok {
						spos := fset.Position(e.Pos())
						sinkID := g.addNode(Node{
							Kind:     KindSink,
							Name:     calleeString(e.Fun),
							File:     spos.Filename,
							Line:     spos.Line,
							SinkRule: rule,
							Severity: sev,
						})
						g.addEdge(fnID, sinkID, EdgeContains)
					}
				case *ast.Ident:
					if looksLikePII(e.Name) {
						g.Nodes[fnID].PII = true
					}
				}
				return true
			})
			pends = append(pends, p)
		}
	}

	// Second pass: now that every function has a node, wire same-package call
	// edges by resolved name.
	for _, p := range pends {
		for _, callee := range p.callees {
			if dstID, ok := g.byFunc[callee]; ok && dstID != p.fnID {
				g.addEdge(p.fnID, dstID, EdgeCalls)
			}
		}
	}

	return g, nil
}

// qualifiedName returns "pkg.Func" for a plain function or "pkg.(Recv).Method"
// for a method, so methods with the same name on different types don't collide.
func qualifiedName(pkg string, fn *ast.FuncDecl) string {
	if fn.Recv != nil && len(fn.Recv.List) > 0 {
		return pkg + ".(" + typeString(fn.Recv.List[0].Type) + ")." + fn.Name.Name
	}
	return pkg + "." + fn.Name.Name
}

// isHTTPHandler reports whether a function's signature marks it as an untrusted
// entrypoint: it takes an *http.Request (the standard-library handler shape).
func isHTTPHandler(fn *ast.FuncDecl) bool {
	if fn.Type.Params == nil {
		return false
	}
	for _, p := range fn.Type.Params.List {
		if strings.Contains(typeString(p.Type), "http.Request") {
			return true
		}
	}
	return false
}

// sameePackageCallee returns the name of a bare-identifier call (a call to a
// function in the same package), used to build internal call edges.
func sameePackageCallee(call *ast.CallExpr) (string, bool) {
	if id, ok := call.Fun.(*ast.Ident); ok {
		return id.Name, true
	}
	return "", false
}
