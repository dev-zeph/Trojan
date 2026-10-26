package graph

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/dev-zeph/trojan/internal/graph/tswasm"
)

// pyRouteMethods are Flask/FastAPI-style decorator methods:
// @app.route(...), @app.get(...), @app.post(...), ...
var pyRouteMethods = map[string]bool{
	"route": true, "get": true, "post": true, "put": true, "delete": true, "patch": true,
}

// pyKnownSinks mirrors build.go's knownSinks for the Python standard library
// and common web-framework surface.
var pyKnownSinks = map[string]struct{ rule, sev string }{
	"eval":                    {"code injection (eval)", "high"},
	"exec":                    {"code injection (exec)", "high"},
	"os.system":               {"OS command execution", "high"},
	"os.popen":                {"OS command execution", "high"},
	"subprocess.call":         {"OS command execution", "high"},
	"subprocess.run":          {"OS command execution", "high"},
	"subprocess.Popen":        {"OS command execution", "high"},
	"subprocess.check_call":   {"OS command execution", "high"},
	"subprocess.check_output": {"OS command execution", "high"},
	"pickle.loads":            {"insecure deserialization", "high"},
	"yaml.load":               {"insecure deserialization (unsafe loader)", "medium"},
	"open":                    {"file access (path traversal)", "medium"},
}

// pySQLMethods are receiver methods that execute SQL (DB-API 2.0 cursor
// convention: cursor.execute(...), conn.executemany(...)).
var pySQLMethods = map[string]bool{"execute": true, "executemany": true, "executescript": true}

// buildFromPythonFiles builds a graph slice for Python source files.
func buildFromPythonFiles(ctx context.Context, rt *tswasm.Runtime, lang tswasm.Language, files []string) (*Graph, error) {
	g := New()

	for _, path := range files {
		src, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		tree, err := rt.Parse(ctx, lang, src)
		if err != nil {
			continue
		}
		root, err := tree.RootNode(ctx)
		if err != nil {
			continue
		}

		b := &pyBuilder{
			g:      g,
			f:      newTSFile(path, src),
			base:   filepath.Base(path),
			byFunc: make(map[string]int),
		}
		if err := b.walk(ctx, root, -1); err != nil {
			continue
		}
		b.resolve()
	}

	return g, nil
}

type pyBuilder struct {
	g      *Graph
	f      *tsFile
	base   string
	byFunc map[string]int

	pendingCalls []pendingCallEdge
}

func (b *pyBuilder) qualify(name string) string { return b.base + "." + name }

func (b *pyBuilder) registerFunc(ctx context.Context, nameNode tswasm.Node, fnNode tswasm.Node, source bool) int {
	name := ""
	if nameNode.Valid() {
		name = b.f.text(ctx, nameNode)
	}
	if name == "" {
		start, _ := fnNode.StartByte(ctx)
		name = "anonymous@" + b.f.path + ":" + strconv.Itoa(b.f.line(start))
	}
	start, _ := fnNode.StartByte(ctx)
	id := b.g.addNode(Node{
		Kind:   KindFunc,
		Name:   b.qualify(name),
		File:   b.f.path,
		Line:   b.f.line(start),
		Source: source,
	})
	b.byFunc[b.qualify(name)] = id
	return id
}

func (b *pyBuilder) walk(ctx context.Context, n tswasm.Node, curFn int) error {
	if isErr, _ := n.IsError(ctx); isErr {
		return nil
	}
	kind, err := n.Kind(ctx)
	if err != nil {
		return err
	}

	switch kind {
	case "decorated_definition":
		nc, err := namedChildren(ctx, n)
		if err != nil {
			return err
		}
		var decorators []tswasm.Node
		var defNode tswasm.Node
		for _, c := range nc {
			ck, _ := c.Kind(ctx)
			switch ck {
			case "decorator":
				decorators = append(decorators, c)
			case "function_definition":
				defNode = c
			}
		}
		if !defNode.Valid() {
			return b.descendChildren(ctx, nc, curFn)
		}
		return b.registerAndDescendDef(ctx, defNode, b.hasRouteDecorator(ctx, decorators), curFn)

	case "function_definition":
		return b.registerAndDescendDef(ctx, n, false, curFn)

	case "call":
		return b.handleCall(ctx, n, curFn)

	case "identifier":
		if curFn >= 0 && looksLikePII(b.f.text(ctx, n)) {
			b.g.Nodes[curFn].PII = true
		}
		return nil
	}

	nc, err := namedChildren(ctx, n)
	if err != nil {
		return err
	}
	return b.descendChildren(ctx, nc, curFn)
}

func (b *pyBuilder) descendChildren(ctx context.Context, nc []tswasm.Node, curFn int) error {
	for _, c := range nc {
		if err := b.walk(ctx, c, curFn); err != nil {
			return err
		}
	}
	return nil
}

// registerAndDescendDef registers a function_definition node (already
// unwrapped from any decorated_definition) and walks its body.
// decoratorSource is true if a route-style decorator was found; the request-
// parameter heuristic (Django/Flask/FastAPI handlers taking `request`) is
// checked either way.
func (b *pyBuilder) registerAndDescendDef(ctx context.Context, defNode tswasm.Node, decoratorSource bool, curFn int) error {
	nc, err := namedChildren(ctx, defNode)
	if err != nil {
		return err
	}
	nameNode, _ := findByKind(ctx, nc, map[string]bool{"identifier": true})
	paramsNode, hasParams := findByKind(ctx, nc, map[string]bool{"parameters": true})

	source := decoratorSource
	if !source && hasParams {
		source = b.hasRequestParam(ctx, paramsNode)
	}

	id := b.registerFunc(ctx, nameNode, defNode, source)
	return b.descendBody(ctx, defNode, id)
}

func (b *pyBuilder) descendBody(ctx context.Context, defNode tswasm.Node, fnID int) error {
	nc, err := namedChildren(ctx, defNode)
	if err != nil {
		return err
	}
	return b.descendChildren(ctx, nc, fnID)
}

// hasRequestParam reports whether a parameter list's first (or, after a
// self/cls receiver, second) parameter is literally named "request", the
// Django/Flask/FastAPI handler convention.
func (b *pyBuilder) hasRequestParam(ctx context.Context, params tswasm.Node) bool {
	nc, err := namedChildren(ctx, params)
	if err != nil || len(nc) == 0 {
		return false
	}
	name := b.paramName(ctx, nc[0])
	if name == "self" || name == "cls" {
		if len(nc) < 2 {
			return false
		}
		name = b.paramName(ctx, nc[1])
	}
	return strings.EqualFold(name, "request")
}

func (b *pyBuilder) paramName(ctx context.Context, n tswasm.Node) string {
	kind, err := n.Kind(ctx)
	if err != nil {
		return ""
	}
	if kind == "identifier" {
		return b.f.text(ctx, n)
	}
	// typed_parameter, default_parameter, typed_default_parameter all carry
	// the identifier as their first named child.
	nc, err := namedChildren(ctx, n)
	if err != nil || len(nc) == 0 {
		return ""
	}
	if k, _ := nc[0].Kind(ctx); k == "identifier" {
		return b.f.text(ctx, nc[0])
	}
	return ""
}

// hasRouteDecorator reports whether any decorator matches a Flask/FastAPI
// route registration: @app.route(...), @app.get(...), @router.post(...).
func (b *pyBuilder) hasRouteDecorator(ctx context.Context, decorators []tswasm.Node) bool {
	for _, d := range decorators {
		nc, err := namedChildren(ctx, d)
		if err != nil || len(nc) == 0 {
			continue
		}
		expr := nc[0]
		exprKind, _ := expr.Kind(ctx)
		var method string
		switch exprKind {
		case "call":
			callNC, err := namedChildren(ctx, expr)
			if err != nil || len(callNC) == 0 {
				continue
			}
			method = attrName(ctx, b.f, callNC[0])
		case "attribute":
			method = attrName(ctx, b.f, expr)
		}
		if pyRouteMethods[method] {
			return true
		}
	}
	return false
}

func (b *pyBuilder) addSink(ctx context.Context, n tswasm.Node, callerID int, rule, sev string) {
	start, _ := n.StartByte(ctx)
	sinkID := b.g.addNode(Node{
		Kind:     KindSink,
		Name:     strings.TrimSpace(b.f.text(ctx, n)),
		File:     b.f.path,
		Line:     b.f.line(start),
		SinkRule: rule,
		Severity: sev,
	})
	b.g.addEdge(callerID, sinkID, EdgeContains)
}

func (b *pyBuilder) handleCall(ctx context.Context, n tswasm.Node, curFn int) error {
	nc, err := namedChildren(ctx, n)
	if err != nil {
		return err
	}
	if len(nc) == 0 {
		return nil
	}
	calleeNode := nc[0]
	calleeText := b.f.text(ctx, calleeNode)
	var argNodes []tswasm.Node
	if len(nc) > 1 {
		argNodes, _ = namedChildren(ctx, nc[1])
	}

	if curFn >= 0 {
		if s, ok := pyKnownSinks[calleeText]; ok {
			b.addSink(ctx, n, curFn, s.rule, s.sev)
		} else if calleeKind, _ := calleeNode.Kind(ctx); calleeKind == "attribute" {
			method := attrName(ctx, b.f, calleeNode)
			if pySQLMethods[method] {
				concat := false
				for _, a := range argNodes {
					if hasUnsafeConcat(ctx, a) {
						concat = true
						break
					}
				}
				if concat {
					b.addSink(ctx, n, curFn, "SQL query built with string concatenation (injection)", "high")
				} else {
					b.addSink(ctx, n, curFn, "SQL query execution", "medium")
				}
			}
		}
	}

	if calleeKind, _ := calleeNode.Kind(ctx); calleeKind == "identifier" && curFn >= 0 {
		b.pendingCalls = append(b.pendingCalls, pendingCallEdge{callerID: curFn, callee: b.qualify(calleeText)})
	}

	if err := b.walk(ctx, calleeNode, curFn); err != nil {
		return err
	}
	for _, a := range argNodes {
		if err := b.walk(ctx, a, curFn); err != nil {
			return err
		}
	}
	return nil
}

func (b *pyBuilder) resolve() {
	for _, p := range b.pendingCalls {
		if dst, ok := b.byFunc[p.callee]; ok && dst != p.callerID {
			b.g.addEdge(p.callerID, dst, EdgeCalls)
		}
	}
}
