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
// exact callee text -> why it's dangerous and how bad. Callees are matched
// both as written and canonicalized through imports, so
// `const { exec } = require("child_process"); exec(cmd)` and
// `import cp from "node:child_process"; cp.exec(cmd)` both hit
// "child_process.exec".
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
// false-positive on unrelated ".query"/".exec" methods). "raw" (knex) only
// counts when its argument is built by interpolation.
var jsSQLMethods = map[string]bool{"query": true, "execute": true, "raw": true, "prepare": true}

// jsRawSQLUnsafe are Prisma escape hatches that run a plain string as SQL.
var jsRawSQLUnsafe = map[string]bool{"$queryRawUnsafe": true, "$executeRawUnsafe": true}

// jsHTTPClients are outbound HTTP calls (canonical callee).
var jsHTTPClients = map[string]bool{
	"fetch": true, "axios": true, "axios.get": true, "axios.post": true, "axios.put": true,
	"axios.patch": true, "axios.delete": true, "axios.request": true, "got": true,
	"got.get": true, "got.post": true, "ky": true, "ky.get": true, "ky.post": true,
	"needle": true, "superagent.get": true, "superagent.post": true,
}

const (
	ruleServiceRole = "Supabase service-role client (bypasses row level security)"
	ruleServerOnly  = "server-only module imported into client code"
)

// buildFromJSFiles builds a graph slice for JavaScript/TypeScript source
// files. lang is the grammar the dispatcher picked for the batch; each file
// is parsed with the grammar matching its own extension when available, so a
// batch that mixes .js and .ts (one call for the whole JS/TS project, which
// is what cross-file import resolution wants) also parses correctly.
//
// Two phases: every file is walked first (functions, calls, sinks,
// datastore access, imports/exports, route registrations), then a project
// pass resolves cross-file references (relative imports, require(),
// tsconfig "paths" aliases), framework entrypoints (Next.js, Express) and
// auth guards.
func buildFromJSFiles(ctx context.Context, rt *tswasm.Runtime, lang tswasm.Language, files []string) (*Graph, error) {
	g := New()
	p := newJSProject(g)

	var tsLang, jsLang *tswasm.Language
	grammar := func(path string) tswasm.Language {
		switch strings.ToLower(filepath.Ext(path)) {
		case ".ts", ".tsx", ".mts", ".cts":
			if tsLang == nil {
				if l, err := rt.TypeScript(ctx); err == nil {
					tsLang = &l
				} else {
					tsLang = &lang
				}
			}
			return *tsLang
		case ".js", ".jsx", ".mjs", ".cjs":
			if jsLang == nil {
				if l, err := rt.JavaScript(ctx); err == nil {
					jsLang = &l
				} else {
					jsLang = &lang
				}
			}
			return *jsLang
		}
		return lang
	}

	for _, path := range files {
		src, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		tree, err := rt.Parse(ctx, grammar(path), src)
		if err != nil {
			continue // unparseable file, skip (same policy as the Go builder)
		}
		root, err := tree.RootNode(ctx)
		if err != nil {
			continue
		}

		b := newJSBuilder(p, path, src)
		b.prepass(ctx, root)
		if err := b.walk(ctx, root, -1); err != nil {
			continue
		}
		b.scanRawHTML()
		p.add(b)
	}

	p.resolve()
	return g, nil
}

// jsImport is one binding a module pulls in from another module:
// `import { a as b } from "./x"` gives local "b" -> {spec: "./x", name: "a"}.
// name is "default" for default imports and whole-module require(), "*"
// for namespace imports.
type jsImport struct{ spec, name string }

// jsMemberRef is `ns.prop` inside a function where ns is an import: a call
// into another module's export (db.query, controllers.getUser).
type jsMemberRef struct {
	fnID       int
	local, key string
}

// jsRoute is one Express-style route registration: receiver.method(path,
// ...middleware, handler).
type jsRoute struct {
	receiver, method, path string
	middleware             []string // names of the middle arguments
	handlerID              int      // inline handler node, or -1
	handlerRef             string   // identifier/member text of a by-reference handler
	pos                    uint32
}

// jsUse is a receiver.use([prefix], ...args) call: global middleware or a
// router mount.
type jsUse struct {
	receiver, prefix string
	args             []jsUseArg
	pos              uint32
}

type jsUseArg struct {
	name string // identifier or callee text
	spec string // set when the argument is an inline require("...")
}

type jsBuilder struct {
	p    *jsProject
	g    *Graph
	f    *tsFile
	base string // file basename, used to namespace function names per file
	abs  string

	byFunc    map[string]int // qualified name -> node id
	shortName map[int]string
	anonCount map[string]int
	nameCount map[string]int

	directive     string // "use client" | "use server" | ""
	serverOnly    bool   // imports "server-only" or next/headers
	imports       map[string]jsImport
	exports       map[string]string // exported name -> local name
	reexports     map[string]jsImport
	starReexports []string
	bindings      map[string]string // module-level binding -> initializer text (trimmed)

	refs          map[int]map[string]bool
	memberRefs    []jsMemberRef
	routes        []*jsRoute
	uses          []*jsUse
	directGuard   map[int]bool
	inlineActions []int
	funcs         []int
	fnRange       map[int][2]uint32 // node id -> source byte span
}

func newJSBuilder(p *jsProject, path string, src []byte) *jsBuilder {
	abs, err := filepath.Abs(path)
	if err != nil {
		abs = path
	}
	return &jsBuilder{
		p: p, g: p.g, f: newTSFile(path, src), base: filepath.Base(path), abs: filepath.Clean(abs),
		byFunc: map[string]int{}, shortName: map[int]string{}, anonCount: map[string]int{}, nameCount: map[string]int{},
		imports: map[string]jsImport{}, exports: map[string]string{}, reexports: map[string]jsImport{},
		bindings: map[string]string{}, refs: map[int]map[string]bool{}, directGuard: map[int]bool{}, fnRange: map[int][2]uint32{},
	}
}

func (b *jsBuilder) qualify(name string) string { return b.base + "." + name }

// registerFunc adds a KindFunc node for a function-like syntax node and
// returns its graph ID. Unnamed functions get a line-free name derived from
// their enclosing function plus an ordinal ("POST.anonymous#1"), so node
// names stay stable when unrelated lines move.
func (b *jsBuilder) registerFunc(ctx context.Context, nameNode tswasm.Node, fnNode tswasm.Node, anonHint string, source bool, curFn int) int {
	name := ""
	if nameNode.Valid() {
		name = strings.Join(strings.Fields(b.f.text(ctx, nameNode)), "")
	}
	return b.registerNamed(ctx, name, fnNode, anonHint, source, curFn)
}

func (b *jsBuilder) registerNamed(ctx context.Context, name string, fnNode tswasm.Node, anonHint string, source bool, curFn int) int {
	if name == "" {
		parent := "module"
		if curFn >= 0 {
			parent = b.shortName[curFn]
		}
		prefix := parent + "." + anonHint
		b.anonCount[prefix]++
		name = prefix + "#" + strconv.Itoa(b.anonCount[prefix])
	}
	start, _ := fnNode.StartByte(ctx)
	id := b.g.addNode(Node{
		Kind:       KindFunc,
		Name:       b.qualify(name),
		File:       b.f.path,
		Line:       b.f.line(start),
		Source:     source,
		ClientSide: b.directive == "use client",
	})
	b.byFunc[b.qualify(name)] = id
	b.shortName[id] = name
	b.funcs = append(b.funcs, id)
	end, _ := fnNode.EndByte(ctx)
	b.fnRange[id] = [2]uint32{start, end}
	return id
}

func (b *jsBuilder) addRef(fnID int, name string) {
	m := b.refs[fnID]
	if m == nil {
		m = map[string]bool{}
		b.refs[fnID] = m
	}
	m[name] = true
}

// walk performs one depth-first pass over the syntax tree, tracking the
// innermost enclosing function (curFn, -1 if none) so calls, sinks, and PII
// touches are attributed to the right node, the same attribution build.go
// gets from calling ast.Inspect once per top-level function, done here in a
// single pass since JS commonly nests functions inside functions.
func (b *jsBuilder) walk(ctx context.Context, n tswasm.Node, curFn int) error {
	if isErr, _ := n.IsError(ctx); isErr {
		// Recover what parsed inside the error. ts.wasm has no TSX dialect,
		// so a .tsx file's JSX regularly turns whole statements (sometimes
		// the program root) into ERROR nodes whose children are still
		// well-formed functions and calls; skipping them would drop every
		// route and query in that file.
		nc, err := namedChildren(ctx, n)
		if err != nil {
			return nil
		}
		// The usual shape of that damage: `function Name(params) { body }`
		// comes apart into identifier, formal_parameters, then the body's
		// statements as loose siblings. Re-attach them to a function named
		// Name so their calls and queries keep an owner.
		owner := curFn
		for i := 0; i < len(nc); i++ {
			k, _ := nc[i].Kind(ctx)
			if k == "identifier" && i+1 < len(nc) {
				if nk, _ := nc[i+1].Kind(ctx); nk == "formal_parameters" {
					owner = b.registerFunc(ctx, nc[i], nc[i], "anonymous", false, curFn)
					start, _ := nc[i].StartByte(ctx)
					end, _ := n.EndByte(ctx)
					b.fnRange[owner] = [2]uint32{start, end}
					continue
				}
			}
			if err := b.walk(ctx, nc[i], owner); err != nil {
				return err
			}
		}
		return nil
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
		id := b.registerFunc(ctx, nameNode, n, "anonymous", false, curFn)
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
		id := b.registerFunc(ctx, nameNode, n, "method", false, curFn)
		return b.descendBody(ctx, n, id)

	case "export_statement":
		// export default (req) => ... / export default async function () {}:
		// an anonymous default export still needs a stable name.
		kids, err := allChildren(ctx, n)
		if err != nil {
			return err
		}
		isDefault := false
		for _, k := range kids {
			if kk, _ := k.Kind(ctx); kk == "default" {
				isDefault = true
			}
		}
		if isDefault && curFn < 0 {
			nc, _ := namedChildren(ctx, n)
			if fnNode, ok := findByKind(ctx, nc, map[string]bool{"arrow_function": true, "function_expression": true, "function": true}); ok {
				id := b.registerNamed(ctx, "default", fnNode, "anonymous", false, curFn)
				b.exports["default"] = "default"
				return b.descendBody(ctx, fnNode, id)
			}
			// export default clerkMiddleware(...) / auth((req) => ...):
			// a wrapped default export gets a binding node too.
			if call, ok := findByKind(ctx, nc, map[string]bool{"call_expression": true}); ok {
				id := b.registerNamed(ctx, "default", call, "anonymous", false, curFn)
				b.exports["default"] = "default"
				return b.walk(ctx, call, id)
			}
		}

	case "variable_declarator":
		nc, err := namedChildren(ctx, n)
		if err != nil {
			return err
		}
		if len(nc) >= 2 {
			b.recordRequire(ctx, nc[0], nc[len(nc)-1])
		}
		if fnNode, ok := findByKind(ctx, nc, jsFunctionLikeKinds); ok {
			nameNode, _ := findByKind(ctx, nc, map[string]bool{"identifier": true})
			id := b.registerFunc(ctx, nameNode, fnNode, "anonymous", false, curFn)
			return b.descendBody(ctx, fnNode, id)
		}
		// Module-level `const supabase = createClient(...)`: give the
		// binding its own node so sinks in the initializer (a service-role
		// client) attach to it and functions that use it link to it.
		if curFn < 0 && len(nc) >= 2 {
			nameNode, value := nc[0], nc[len(nc)-1]
			nk, _ := nameNode.Kind(ctx)
			if nk == "identifier" && !b.isRequireCall(ctx, value) && containsKind(ctx, value, map[string]bool{"call_expression": true, "new_expression": true}, 6) {
				name := b.f.text(ctx, nameNode)
				b.bindings[name] = strings.Join(strings.Fields(b.f.text(ctx, value)), " ")
				id := b.registerNamed(ctx, name, value, "binding", false, curFn)
				return b.walk(ctx, value, id)
			}
		}
		return b.descendChildren(ctx, nc, curFn)

	case "assignment_expression":
		nc, err := namedChildren(ctx, n)
		if err != nil {
			return err
		}
		if len(nc) >= 2 {
			left := nc[0]
			leftText := b.f.text(ctx, left)
			if fnNode, ok := findByKind(ctx, nc[1:], jsFunctionLikeKinds); ok {
				id := b.registerFunc(ctx, left, fnNode, "anonymous", false, curFn)
				if name := cjsExportName(leftText); name != "" {
					b.exports[name] = strings.Join(strings.Fields(leftText), "")
				}
				return b.descendBody(ctx, fnNode, id)
			}
			// x.innerHTML = <anything>: classic DOM XSS sink.
			if leftKind, _ := left.Kind(ctx); leftKind == "member_expression" {
				if prop := attrName(ctx, b.f, left); prop == "innerHTML" {
					if curFn >= 0 {
						b.addSink(ctx, n, curFn, leftText, "unescaped HTML written to the DOM (XSS)", "high")
					}
				}
			}
		}
		return b.descendChildren(ctx, nc, curFn)

	case "arrow_function", "function_expression", "function", "generator_function":
		// Reached directly (not through a declarator/assignment/route-arg
		// special case): an anonymous callback. Still worth its own node so
		// calls/sinks inside it attribute correctly instead of leaking into
		// the outer function; the enclosing function "calls" it, since a
		// callback runs as part of the code that defines it.
		id := b.registerFunc(ctx, tswasm.Node{}, n, "anonymous", false, curFn)
		if curFn >= 0 {
			b.g.addEdge(curFn, id, EdgeCalls)
		}
		return b.descendBody(ctx, n, id)

	case "call_expression":
		return b.handleCall(ctx, n, curFn)

	case "identifier", "shorthand_property_identifier":
		if curFn >= 0 {
			name := b.f.text(ctx, n)
			if looksLikePII(name) {
				b.g.Nodes[curFn].PII = true
			}
			b.addRef(curFn, name)
		}
		return nil

	case "property_identifier":
		if curFn >= 0 && looksLikePII(b.f.text(ctx, n)) {
			b.g.Nodes[curFn].PII = true
		}
		return nil

	case "member_expression":
		// ns.prop where ns is an import: remember it so the project pass can
		// link to that module's export.
		if curFn >= 0 {
			if nc, err := namedChildren(ctx, n); err == nil && len(nc) == 2 {
				if ok, _ := nc[0].Kind(ctx); ok == "identifier" {
					local := b.f.text(ctx, nc[0])
					if _, imported := b.imports[local]; imported {
						b.memberRefs = append(b.memberRefs, jsMemberRef{fnID: curFn, local: local, key: b.f.text(ctx, nc[1])})
					}
				}
			}
		}

	case "statement_block":
		// An inline server action: a function whose body opens with
		// "use server".
		if curFn >= 0 && b.directive != "use server" && firstDirective(ctx, b.f, n) == "use server" {
			b.inlineActions = append(b.inlineActions, curFn)
		}
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

// addSink records a sink node named after its callee (never its argument
// text) and links it to the function containing it.
func (b *jsBuilder) addSink(ctx context.Context, n tswasm.Node, callerID int, callee, rule, sev string) {
	start, _ := n.StartByte(ctx)
	b.addSinkAt(b.f.line(start), callerID, callee, rule, sev)
}

// addSinkAt is addSink for a sink found by position rather than by syntax
// node (see scanRawHTML).
func (b *jsBuilder) addSinkAt(line, callerID int, callee, rule, sev string) {
	sinkID := b.g.addNode(Node{
		Kind:       KindSink,
		Name:       sinkName(callee),
		File:       b.f.path,
		Line:       line,
		SinkRule:   rule,
		Severity:   sev,
		ClientSide: b.directive == "use client",
	})
	b.g.addEdge(callerID, sinkID, EdgeContains)
}

// canonicalCallee rewrites a callee through the file's imports of npm/node
// modules: `exec` imported from "child_process" -> "child_process.exec",
// `cp.exec` with cp = require("node:child_process") -> "child_process.exec".
func (b *jsBuilder) canonicalCallee(callee string) string {
	head, rest := callee, ""
	if i := strings.Index(callee, "."); i >= 0 {
		head, rest = callee[:i], callee[i:]
	}
	imp, ok := b.imports[head]
	if !ok || isRelativeSpec(imp.spec) {
		return callee
	}
	mod := strings.TrimPrefix(imp.spec, "node:")
	mod = strings.TrimSuffix(mod, "/promises")
	if imp.name == "default" || imp.name == "*" {
		return mod + rest
	}
	return mod + "." + imp.name + rest
}

// handleCall processes a call_expression: sinks, datastore access, auth
// guard calls, and Express/Koa-style route and middleware registration.
func (b *jsBuilder) handleCall(ctx context.Context, n tswasm.Node, curFn int) error {
	nc, err := namedChildren(ctx, n)
	if err != nil {
		return err
	}
	if len(nc) == 0 {
		return nil
	}
	calleeNode := nc[0]
	calleeText := strings.Join(strings.Fields(b.f.text(ctx, calleeNode)), "")
	calleeKind, _ := calleeNode.Kind(ctx)
	var argNodes []tswasm.Node
	argsText := ""
	if len(nc) > 1 {
		argNodes, _ = namedChildren(ctx, nc[1])
		argsText = b.f.text(ctx, nc[1])
	}

	if curFn >= 0 {
		b.detectSinks(ctx, n, curFn, calleeNode, calleeKind, calleeText, argNodes, argsText)
		// true = self-blocking guard; false = a session read that only
		// counts if the function also refuses the request (see guards).
		if isGuardCall(calleeText) {
			b.directGuard[curFn] = b.directGuard[curFn] || isSelfBlockingGuard(calleeText)
		}
		if calleeKind == "member_expression" {
			steps, root := flattenCallChain(ctx, b.f, n)
			if a, ok := matchDataAccess(ctx, b.f, steps, root); ok {
				b.p.stores.add(b.f.path, curFn, a)
			}
		}
	}

	if calleeKind == "member_expression" {
		method := attrName(ctx, b.f, calleeNode)
		recvNode, _ := firstNamedChild(ctx, calleeNode)
		receiver := strings.TrimSpace(b.f.text(ctx, recvNode))
		pos, _ := n.StartByte(ctx)

		// Express/Koa-style route registration: app.get('/path', handler)
		// or router.post('/path', mw, handler): the last argument is the
		// untrusted entrypoint, the ones in between are middleware.
		if jsRouteMethods[method] && len(argNodes) >= 2 && b.isRouterReceiver(receiver) {
			if path, ok := literalString(ctx, b.f, argNodes[0]); ok {
				r := &jsRoute{receiver: receiver, method: strings.ToUpper(method), path: path, handlerID: -1, pos: pos}
				for _, mw := range argNodes[1 : len(argNodes)-1] {
					r.middleware = append(r.middleware, b.argName(ctx, mw))
				}
				b.routes = append(b.routes, r)
				last := argNodes[len(argNodes)-1]
				lastKind, _ := last.Kind(ctx)
				if jsFunctionLikeKinds[lastKind] {
					name := r.method + " " + path
					b.nameCount[name]++
					if c := b.nameCount[name]; c > 1 {
						name += "#" + strconv.Itoa(c)
					}
					id := b.registerNamed(ctx, name, last, "route_handler", true, -1)
					r.handlerID = id
					if err := b.descendBody(ctx, last, id); err != nil {
						return err
					}
					// don't re-walk `last` generically below
					return b.walkCallRemainder(ctx, calleeNode, argNodes, curFn, last)
				}
				if lastKind == "identifier" || lastKind == "member_expression" {
					r.handlerRef = strings.TrimSpace(b.f.text(ctx, last))
				}
			}
		}

		// app.use([prefix], ...middleware | router)
		if method == "use" && len(argNodes) > 0 && b.isRouterReceiver(receiver) {
			u := &jsUse{receiver: receiver, pos: pos}
			for i, a := range argNodes {
				if i == 0 {
					if s, ok := literalString(ctx, b.f, a); ok {
						u.prefix = s
						continue
					}
				}
				arg := jsUseArg{name: b.argName(ctx, a)}
				if spec, ok := b.requireSpec(ctx, a); ok {
					arg.spec = spec
				}
				u.args = append(u.args, arg)
			}
			b.uses = append(b.uses, u)
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

// detectSinks classifies one call inside a function.
func (b *jsBuilder) detectSinks(ctx context.Context, n tswasm.Node, curFn int, calleeNode tswasm.Node, calleeKind, calleeText string, argNodes []tswasm.Node, argsText string) {
	canon := b.canonicalCallee(calleeText)
	if s, ok := jsKnownSinks[calleeText]; ok {
		b.addSink(ctx, n, curFn, calleeText, s.rule, s.sev)
		return
	}
	if s, ok := jsKnownSinks[canon]; ok {
		b.addSink(ctx, n, curFn, calleeText, s.rule, s.sev)
		return
	}
	if isServiceRoleClient(calleeText, argsText) {
		b.addSink(ctx, n, curFn, calleeText, ruleServiceRole, "medium")
		return
	}
	if jsHTTPClients[canon] && b.directive != "use client" && len(argNodes) > 0 {
		if s, ok := literalString(ctx, b.f, argNodes[0]); ok && (strings.HasPrefix(s, "/") || s == "") {
			return // same-origin relative call
		}
		rule := "outbound HTTP request"
		if _, ok := literalString(ctx, b.f, argNodes[0]); !ok {
			rule = "outbound HTTP request to a computed URL (possible SSRF)"
		}
		b.addSink(ctx, n, curFn, calleeText, rule, "medium")
		return
	}
	if calleeKind != "member_expression" {
		return
	}
	method := attrName(ctx, b.f, calleeNode)
	if jsRawSQLUnsafe[method] {
		b.addSink(ctx, n, curFn, calleeText, "raw SQL from a string (Prisma "+method+")", "high")
		return
	}
	if jsSQLMethods[method] {
		if len(argNodes) > 0 {
			start, _ := n.StartByte(ctx)
			for _, a := range sqlTables(b.f.text(ctx, argNodes[0])) {
				a.key = start
				b.p.stores.add(b.f.path, curFn, a)
			}
		}
		concat := false
		for _, a := range argNodes {
			if hasUnsafeConcat(ctx, b.f, a) {
				concat = true
				break
			}
		}
		if concat {
			rule := RuleSQLConcat
			if b.sqlFromRequest(ctx, curFn, argNodes) {
				rule = RuleSQLFromInput
			}
			b.addSink(ctx, n, curFn, calleeText, rule, "high")
		} else if method != "raw" {
			b.addSink(ctx, n, curFn, calleeText, "SQL query execution", "medium")
		}
	}
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

// isRouterReceiver reports whether a call receiver plausibly is an Express
// app or router: a binding initialized with express()/Router()/... in this
// file, or one of the conventional names. This keeps cache.get(key, fn) and
// $.get(url, cb) from becoming routes.
func (b *jsBuilder) isRouterReceiver(receiver string) bool {
	if init, ok := b.bindings[receiver]; ok {
		l := strings.ToLower(init)
		for _, k := range []string{"express", "router", "fastify", "koa", "hono", "polka", "restify"} {
			if strings.Contains(l, k) {
				return true
			}
		}
	}
	switch receiver {
	case "app", "router", "server", "api", "routes", "route", "r":
		return true
	}
	return strings.HasSuffix(receiver, "Router") || strings.HasSuffix(receiver, "router") || strings.HasSuffix(receiver, "App")
}

// argName renders a middleware/handler argument as a name: an identifier,
// a member path (controllers.getUser), or a call's callee
// (passport.authenticate("jwt") -> "passport.authenticate").
func (b *jsBuilder) argName(ctx context.Context, a tswasm.Node) string {
	k, _ := a.Kind(ctx)
	if k == "call_expression" {
		if c, ok := firstNamedChild(ctx, a); ok {
			return strings.Join(strings.Fields(b.f.text(ctx, c)), "")
		}
	}
	if k == "identifier" || k == "member_expression" {
		return strings.Join(strings.Fields(b.f.text(ctx, a)), "")
	}
	return ""
}

func firstNamedChild(ctx context.Context, n tswasm.Node) (tswasm.Node, bool) {
	nc, err := namedChildren(ctx, n)
	if err != nil || len(nc) == 0 {
		return tswasm.Node{}, false
	}
	return nc[0], true
}

// containsKind reports whether n or a descendant (up to depth levels) has
// one of kinds.
func containsKind(ctx context.Context, n tswasm.Node, kinds map[string]bool, depth int) bool {
	k, _ := n.Kind(ctx)
	if kinds[k] {
		return true
	}
	if depth == 0 || jsFunctionLikeKinds[k] {
		return false
	}
	nc, err := namedChildren(ctx, n)
	if err != nil {
		return false
	}
	for _, c := range nc {
		if containsKind(ctx, c, kinds, depth-1) {
			return true
		}
	}
	return false
}

// firstDirective returns the directive prologue string ("use client",
// "use server") if the first statement of a program or statement_block is a
// bare string expression, else "".
func firstDirective(ctx context.Context, f *tsFile, block tswasm.Node) string {
	nc, err := namedChildren(ctx, block)
	if err != nil {
		return ""
	}
	for _, c := range nc {
		k, _ := c.Kind(ctx)
		if k == "comment" || k == "hash_bang_line" {
			continue
		}
		if k != "expression_statement" {
			return ""
		}
		s, ok := firstNamedChild(ctx, c)
		if !ok {
			return ""
		}
		v, ok := literalString(ctx, f, s)
		if !ok {
			return ""
		}
		return v
	}
	return ""
}

// guards returns the functions of this file that check auth in their own
// body: a self-blocking guard call, or a session read in a function that
// also refuses the request.
func (b *jsBuilder) guards() []int {
	var out []int
	for _, id := range sortedKeys(b.directGuard) {
		if b.directGuard[id] {
			out = append(out, id)
			continue
		}
		if r, ok := b.fnRange[id]; ok && int(r[1]) <= len(b.f.src) && blocksRequest(string(b.f.src[r[0]:r[1]])) {
			out = append(out, id)
		}
	}
	return out
}
