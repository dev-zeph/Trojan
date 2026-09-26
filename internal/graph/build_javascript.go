package graph

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/dev-zeph/trojan/internal/graph/tswasm"
)

// jsFunctionLikeKinds are the tree-sitter-javascript/typescript node kinds
// that introduce a function body. method_definition covers class methods;
// the rest cover declarations, expressions, and arrow functions.
var jsFunctionLikeKinds = map[string]bool{
	"function_declaration":           true,
	"function_expression":            true,
	"function":                       true,
	"generator_function":             true,
	"generator_function_declaration": true,
	"arrow_function":                 true,
	"method_definition":              true,
}

// jsRouteMethods are Express/Koa/Fastify-style route registration method
// names: app.get(path, handler), router.post(path, handler), ...
var jsRouteMethods = map[string]bool{
	"get": true, "post": true, "put": true, "delete": true, "patch": true, "all": true,
}

// jsKnownSinks mirrors build.go's knownSinks for the Node.js/browser surface:
// exact callee text -> why it's dangerous and how bad.
var jsKnownSinks = map[string]struct{ rule, sev string }{
	"eval":                       {"code injection (eval)", "high"},
	"Function":                   {"code injection (new Function)", "high"},
	"child_process.exec":         {"OS command execution", "high"},
	"child_process.execSync":     {"OS command execution", "high"},
	"child_process.spawn":        {"OS command execution", "high"},
	"child_process.spawnSync":    {"OS command execution", "high"},
	"child_process.execFile":     {"OS command execution", "high"},
	"child_process.execFileSync": {"OS command execution", "high"},
	"fs.writeFile":               {"file write (path traversal)", "medium"},
	"fs.writeFileSync":           {"file write (path traversal)", "medium"},
	"fs.appendFile":              {"file write (path traversal)", "medium"},
	"fs.appendFileSync":          {"file write (path traversal)", "medium"},
	"document.write":             {"unescaped HTML written to DOM (XSS)", "high"},
}

// jsSQLMethods are receiver methods that execute SQL, matched by method name
// (same limitation as build.go's sqlMethods: no type resolution, so this can
// false-positive on unrelated ".query"/".exec" methods).
var jsSQLMethods = map[string]bool{"query": true, "execute": true}

// buildFromJSFiles builds a graph slice for JavaScript/TypeScript source
// files. lang selects the grammar (JavaScript vs TypeScript); both share
// this extraction logic since TypeScript's grammar is a superset of
// JavaScript's for the constructs this package cares about.
func buildFromJSFiles(ctx context.Context, rt *tswasm.Runtime, lang tswasm.Language, files []string) (*Graph, error) {
	g := New()

	for _, path := range files {
		src, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		tree, err := rt.Parse(ctx, lang, src)
		if err != nil {
			continue // unparseable file, skip (same policy as the Go builder)
		}
		root, err := tree.RootNode(ctx)
		if err != nil {
			continue
		}

		b := &jsBuilder{
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

type jsBuilder struct {
	g      *Graph
	f      *tsFile
	base   string // file basename, used to namespace function names per file
	byFunc map[string]int

	pendingCalls  []pendingCallEdge
	pendingSource []string // function names that should be marked Source once resolved
}

func (b *jsBuilder) qualify(name string) string { return b.base + "." + name }

// registerFunc adds a KindFunc node for a function-like syntax node, pushes
// it as the "current function" for the walk of its body, and returns its
// graph ID. anonName is used when no better name can be recovered (a bare
// callback with no enclosing declarator/assignment/property).
func (b *jsBuilder) registerFunc(ctx context.Context, nameNode tswasm.Node, fnNode tswasm.Node, anonHint string, source bool) int {
	name := ""
	if nameNode.Valid() {
		name = b.f.text(ctx, nameNode)
	}
	if name == "" {
		start, _ := fnNode.StartByte(ctx)
		name = anonHint + "@" + b.f.path + ":" + strconv.Itoa(b.f.line(start))
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

// walk performs one depth-first pass over the syntax tree, tracking the
// innermost enclosing function (curFn, -1 if none) so calls, sinks, and PII
// touches are attributed to the right node, the same attribution build.go
// gets from calling ast.Inspect once per top-level function, done here in a
// single pass since JS commonly nests functions inside functions.
func (b *jsBuilder) walk(ctx context.Context, n tswasm.Node, curFn int) error {
	if isErr, _ := n.IsError(ctx); isErr {
		return nil // skip unparseable subtrees rather than report garbage
	}
	kind, err := n.Kind(ctx)
	if err != nil {
		return err
	}

	switch kind {
	case "function_declaration", "generator_function_declaration":
		nc, err := namedChildren(ctx, n)
		if err != nil {
			return err
		}
		nameNode, _ := findByKind(ctx, nc, map[string]bool{"identifier": true})
		id := b.registerFunc(ctx, nameNode, n, "anonymous", false)
		return b.descendBody(ctx, n, id)

	case "method_definition":
		nc, err := namedChildren(ctx, n)
		if err != nil {
			return err
		}
		nameNode, ok := findByKind(ctx, nc, map[string]bool{"property_identifier": true})
		if !ok {
			nameNode, _ = findByKind(ctx, nc, map[string]bool{"private_property_identifier": true})
		}
		id := b.registerFunc(ctx, nameNode, n, "method", false)
		return b.descendBody(ctx, n, id)

	case "variable_declarator":
		nc, err := namedChildren(ctx, n)
		if err != nil {
			return err
		}
		if fnNode, ok := findByKind(ctx, nc, jsFunctionLikeKinds); ok {
			nameNode, _ := findByKind(ctx, nc, map[string]bool{"identifier": true})
			id := b.registerFunc(ctx, nameNode, fnNode, "anonymous", false)
			return b.descendBody(ctx, fnNode, id)
		}
		return b.descendChildren(ctx, nc, curFn)

	case "assignment_expression":
		nc, err := namedChildren(ctx, n)
		if err != nil {
			return err
		}
		if len(nc) >= 2 {
			left := nc[0]
			if fnNode, ok := findByKind(ctx, nc[1:], jsFunctionLikeKinds); ok {
				id := b.registerFunc(ctx, left, fnNode, "anonymous", false)
				return b.descendBody(ctx, fnNode, id)
			}
			// x.innerHTML = <anything>: classic DOM XSS sink.
			if leftKind, _ := left.Kind(ctx); leftKind == "member_expression" {
				if prop := attrName(ctx, b.f, left); prop == "innerHTML" {
					if curFn >= 0 {
						b.addSink(ctx, n, curFn, "unescaped HTML written to the DOM (XSS)", "high")
					}
				}
			}
		}
		return b.descendChildren(ctx, nc, curFn)

	case "arrow_function", "function_expression", "function", "generator_function":
		// Reached directly (not through a declarator/assignment/route-arg
		// special case): an anonymous callback. Still worth its own node so
		// calls/sinks inside it attribute correctly instead of leaking into
		// the outer function.
		id := b.registerFunc(ctx, tswasm.Node{}, n, "anonymous", false)
		return b.descendBody(ctx, n, id)

	case "call_expression":
		return b.handleCall(ctx, n, curFn)

	case "identifier", "property_identifier", "shorthand_property_identifier":
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

// descendBody walks a function-like node's own children (parameters, body)
// with itself as the new enclosing function, without re-triggering the
// function-kind case in walk (which would register a duplicate node).
func (b *jsBuilder) descendBody(ctx context.Context, fnNode tswasm.Node, fnID int) error {
	nc, err := namedChildren(ctx, fnNode)
	if err != nil {
		return err
	}
	return b.descendChildren(ctx, nc, fnID)
}

func (b *jsBuilder) descendChildren(ctx context.Context, nc []tswasm.Node, curFn int) error {
	for _, c := range nc {
		if err := b.walk(ctx, c, curFn); err != nil {
			return err
		}
	}
	return nil
}

func (b *jsBuilder) addSink(ctx context.Context, n tswasm.Node, callerID int, rule, sev string) {
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

// handleCall processes a call_expression: sink detection, same-file call
// edges (deferred to resolve()), and Express/Koa-style route source
// detection.
func (b *jsBuilder) handleCall(ctx context.Context, n tswasm.Node, curFn int) error {
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

	// Sink detection.
	if curFn >= 0 {
		if s, ok := jsKnownSinks[calleeText]; ok {
			b.addSink(ctx, n, curFn, s.rule, s.sev)
		} else if calleeKind, _ := calleeNode.Kind(ctx); calleeKind == "member_expression" {
			method := attrName(ctx, b.f, calleeNode)
			if jsSQLMethods[method] {
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

	// Same-file call edge: bare identifier callee, resolved once every
	// function in the file is registered.
	if calleeKind, _ := calleeNode.Kind(ctx); calleeKind == "identifier" && curFn >= 0 {
		b.pendingCalls = append(b.pendingCalls, pendingCallEdge{callerID: curFn, callee: b.qualify(calleeText)})
	}

	// Express/Koa-style route registration: app.get('/path', handler) or
	// router.post('/path', a, b, handler): the last argument, if it's a
	// function, is the untrusted entrypoint.
	if calleeKind, _ := calleeNode.Kind(ctx); calleeKind == "member_expression" {
		method := attrName(ctx, b.f, calleeNode)
		if jsRouteMethods[method] && len(argNodes) > 0 {
			last := argNodes[len(argNodes)-1]
			lastKind, _ := last.Kind(ctx)
			if jsFunctionLikeKinds[lastKind] {
				id := b.registerFunc(ctx, tswasm.Node{}, last, "route_handler", true)
				if err := b.descendBody(ctx, last, id); err != nil {
					return err
				}
				// don't re-walk `last` generically below
				return b.walkCallRemainder(ctx, calleeNode, argNodes, curFn, last)
			}
			if lastKind == "identifier" {
				b.pendingSource = append(b.pendingSource, b.qualify(b.f.text(ctx, last)))
			}
		}
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

// walkCallRemainder walks a call's callee and arguments except skip, which
// the caller has already fully processed (the route handler function).
func (b *jsBuilder) walkCallRemainder(ctx context.Context, calleeNode tswasm.Node, argNodes []tswasm.Node, curFn int, skip tswasm.Node) error {
	if err := b.walk(ctx, calleeNode, curFn); err != nil {
		return err
	}
	skipStart, _ := skip.StartByte(ctx)
	for _, a := range argNodes {
		aStart, _ := a.StartByte(ctx)
		if aStart == skipStart {
			continue
		}
		if err := b.walk(ctx, a, curFn); err != nil {
			return err
		}
	}
	return nil
}

// resolve wires deferred call edges and route-handler-by-reference sources
// now that every function in the file has a graph node.
func (b *jsBuilder) resolve() {
	for _, p := range b.pendingCalls {
		if dst, ok := b.byFunc[p.callee]; ok && dst != p.callerID {
			b.g.addEdge(p.callerID, dst, EdgeCalls)
		}
	}
	for _, name := range b.pendingSource {
		if id, ok := b.byFunc[name]; ok {
			b.g.Nodes[id].Source = true
		}
	}
}
