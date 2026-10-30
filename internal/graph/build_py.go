package graph

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/dev-zeph/trojan/internal/graph/tswasm"
)

// pyRouteMethods are Flask/FastAPI-style decorator methods:
// @app.route(...), @app.get(...), @app.post(...), ...
var pyRouteMethods = map[string]bool{
	"route": true, "get": true, "post": true, "put": true, "delete": true, "patch": true,
	"api_route": true, "websocket": true,
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

// pyHTTPClients are outbound HTTP calls.
var pyHTTPClients = map[string]bool{
	"requests.get": true, "requests.post": true, "requests.put": true, "requests.patch": true,
	"requests.delete": true, "requests.request": true, "httpx.get": true, "httpx.post": true,
	"httpx.put": true, "httpx.delete": true, "httpx.request": true, "urllib.request.urlopen": true,
	"urlopen": true,
}

// pySQLMethods are receiver methods that execute SQL (DB-API 2.0 cursor
// convention: cursor.execute(...), conn.executemany(...)).
var pySQLMethods = map[string]bool{"execute": true, "executemany": true, "executescript": true}

// pyDependsRe finds FastAPI dependencies: Depends(get_current_user),
// Security(oauth2_scheme).
var pyDependsRe = regexp.MustCompile(`\b(?:Depends|Security)\(\s*([\w.]+)`)

// buildFromPythonFiles builds a graph slice for Python source files. Like the
// JS builder it walks every file first and then resolves cross-file
// references (`from db import get_conn`, `import db; db.get_conn()`,
// relative imports) and guards in a project pass.
func buildFromPythonFiles(ctx context.Context, rt *tswasm.Runtime, lang tswasm.Language, files []string) (*Graph, error) {
	g := New()
	p := newPyProject(g)

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

		b := newPyBuilder(p, path, src)
		if err := b.walk(ctx, root, -1); err != nil {
			continue
		}
		p.add(b)
	}

	p.resolve()
	return g, nil
}

// pyImport is one imported binding: `from pkg.mod import a as b` gives local
// "b" -> {module "pkg.mod", name "a"}; `import pkg.mod as m` gives "m" ->
// {module "pkg.mod"} (name "" = the module itself). level counts leading
// dots of a relative import.
type pyImport struct {
	module, name string
	level        int
}

type pyMemberRef struct {
	fnID        int
	local, attr string
}

type pyBuilder struct {
	p      *pyProject
	g      *Graph
	f      *tsFile
	base   string
	abs    string
	byFunc map[string]int

	imports          map[string]pyImport
	refs             map[int]map[string]bool
	memberRefs       []pyMemberRef
	directGuard      map[int]bool
	routeGuard       map[int]bool
	guardedReceivers map[string]bool // APIRouter(dependencies=[Depends(auth)])
	anon             int
	// heuristicSource marks functions that are sources only because their
	// first parameter is named request; dependencies names every
	// Depends(x) target. A FastAPI dependency taking `request` is not an
	// entrypoint of its own, so the project pass clears those.
	heuristicSource map[int]bool
	dependencies    map[string]bool
	fnRange         map[int][2]uint32
}

func newPyBuilder(p *pyProject, path string, src []byte) *pyBuilder {
	abs, err := filepath.Abs(path)
	if err != nil {
		abs = path
	}
	return &pyBuilder{
		p: p, g: p.g, f: newTSFile(path, src), base: filepath.Base(path), abs: filepath.Clean(abs),
		byFunc: map[string]int{}, imports: map[string]pyImport{}, refs: map[int]map[string]bool{},
		directGuard: map[int]bool{}, routeGuard: map[int]bool{}, guardedReceivers: map[string]bool{},
		heuristicSource: map[int]bool{}, dependencies: map[string]bool{}, fnRange: map[int][2]uint32{},
	}
}

func (b *pyBuilder) qualify(name string) string { return b.base + "." + name }

func (b *pyBuilder) registerFunc(ctx context.Context, nameNode tswasm.Node, fnNode tswasm.Node, source bool) int {
	name := ""
	if nameNode.Valid() {
		name = b.f.text(ctx, nameNode)
	}
	if name == "" {
		b.anon++
		name = "anonymous#" + strconv.Itoa(b.anon)
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
	end, _ := fnNode.EndByte(ctx)
	b.fnRange[id] = [2]uint32{start, end}
	return id
}

// guards mirrors jsBuilder.guards.
func (b *pyBuilder) guards() []int {
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

func (b *pyBuilder) addRef(fnID int, name string) {
	m := b.refs[fnID]
	if m == nil {
		m = map[string]bool{}
		b.refs[fnID] = m
	}
	m[name] = true
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
	case "import_statement", "import_from_statement":
		b.recordImport(ctx, n, kind)
		return nil

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
		isRoute, guarded := b.classifyDecorators(ctx, decorators)
		return b.registerAndDescendDef(ctx, defNode, isRoute, guarded, curFn)

	case "function_definition":
		return b.registerAndDescendDef(ctx, n, false, false, curFn)

	case "assignment":
		// Module-level `supabase = create_client(...)`: a binding node, so
		// functions that use it link to it (and to any sink it holds).
		if curFn < 0 {
			nc, err := namedChildren(ctx, n)
			if err == nil && len(nc) >= 2 {
				left, right := nc[0], nc[len(nc)-1]
				if lk, _ := left.Kind(ctx); lk == "identifier" && containsKind(ctx, right, map[string]bool{"call": true}, 4) {
					name := b.f.text(ctx, left)
					rt := b.f.text(ctx, right)
					if strings.Contains(rt, "Router(") {
						for _, m := range pyDependsRe.FindAllStringSubmatch(rt, -1) {
							if isAuthLikeName(m[1]) {
								b.guardedReceivers[name] = true
							}
						}
					}
					id := b.registerFunc(ctx, left, n, false)
					return b.walk(ctx, right, id)
				}
			}
		}

	case "call":
		return b.handleCall(ctx, n, curFn)

	case "attribute":
		// Only the object is a reference; the attribute name is not.
		nc, err := namedChildren(ctx, n)
		if err != nil || len(nc) < 2 {
			return err
		}
		if curFn >= 0 {
			attr := b.f.text(ctx, nc[len(nc)-1])
			if looksLikePII(attr) {
				b.g.Nodes[curFn].PII = true
			}
			if attr == "is_authenticated" && !b.directGuard[curFn] {
				b.directGuard[curFn] = false // candidate: counts if the function refuses (see guards)
			}
			if ok, _ := nc[0].Kind(ctx); ok == "identifier" {
				local := b.f.text(ctx, nc[0])
				if _, imported := b.imports[local]; imported {
					b.memberRefs = append(b.memberRefs, pyMemberRef{fnID: curFn, local: local, attr: attr})
				}
			}
		}
		return b.walk(ctx, nc[0], curFn)

	case "keyword_argument":
		nc, err := namedChildren(ctx, n)
		if err != nil || len(nc) < 2 {
			return err
		}
		return b.walk(ctx, nc[len(nc)-1], curFn)

	case "identifier":
		if curFn >= 0 {
			name := b.f.text(ctx, n)
			if looksLikePII(name) {
				b.g.Nodes[curFn].PII = true
			}
			b.addRef(curFn, name)
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
// checked either way. A FastAPI Depends(get_current_user)-style parameter
// gates the route.
func (b *pyBuilder) registerAndDescendDef(ctx context.Context, defNode tswasm.Node, decoratorSource, guarded bool, curFn int) error {
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
	if hasParams {
		for _, m := range pyDependsRe.FindAllStringSubmatch(b.f.text(ctx, paramsNode), -1) {
			b.dependencies[m[1]] = true
			if isAuthLikeName(m[1]) {
				guarded = true
			}
		}
	}

	id := b.registerFunc(ctx, nameNode, defNode, source)
	if source && !decoratorSource {
		b.heuristicSource[id] = true
	}
	if guarded {
		b.routeGuard[id] = true
	}
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

// classifyDecorators reports whether any decorator registers a Flask/FastAPI
// route (@app.route(...), @router.post(...)) and whether the stack gates it
// with auth: @login_required, @jwt_required(), dependencies=[Depends(auth)]
// on the route decorator, or a route on an APIRouter created with auth
// dependencies.
func (b *pyBuilder) classifyDecorators(ctx context.Context, decorators []tswasm.Node) (isRoute, guarded bool) {
	for _, d := range decorators {
		nc, err := namedChildren(ctx, d)
		if err != nil || len(nc) == 0 {
			continue
		}
		expr := nc[0]
		exprKind, _ := expr.Kind(ctx)
		var method, receiver, full string
		switch exprKind {
		case "call":
			callNC, err := namedChildren(ctx, expr)
			if err != nil || len(callNC) == 0 {
				continue
			}
			full = b.f.text(ctx, callNC[0])
			if ck, _ := callNC[0].Kind(ctx); ck == "attribute" {
				method = attrName(ctx, b.f, callNC[0])
				if obj, ok := firstNamedChild(ctx, callNC[0]); ok {
					receiver = b.f.text(ctx, obj)
				}
			}
		case "attribute":
			full = b.f.text(ctx, expr)
			method = attrName(ctx, b.f, expr)
		case "identifier":
			full = b.f.text(ctx, expr)
		}
		if pyRouteMethods[method] {
			isRoute = true
			if b.guardedReceivers[receiver] {
				guarded = true
			}
			for _, m := range pyDependsRe.FindAllStringSubmatch(b.f.text(ctx, d), -1) {
				if isAuthLikeName(m[1]) {
					guarded = true
				}
			}
			continue
		}
		if isAuthLikeName(full) {
			guarded = true
		}
	}
	return isRoute, guarded
}

func (b *pyBuilder) addSink(ctx context.Context, n tswasm.Node, callerID int, callee, rule, sev string) {
	start, _ := n.StartByte(ctx)
	sinkID := b.g.addNode(Node{
		Kind:     KindSink,
		Name:     sinkName(callee),
		File:     b.f.path,
		Line:     b.f.line(start),
		SinkRule: rule,
		Severity: sev,
	})
	b.g.addEdge(callerID, sinkID, EdgeContains)
}

// canonicalCallee rewrites a callee through `from subprocess import run` /
// `import subprocess as sp` imports of non-project modules.
func (b *pyBuilder) canonicalCallee(callee string) string {
	head, rest := callee, ""
	if i := strings.Index(callee, "."); i >= 0 {
		head, rest = callee[:i], callee[i:]
	}
	imp, ok := b.imports[head]
	if !ok || imp.level > 0 {
		return callee
	}
	if imp.name == "" {
		return imp.module + rest
	}
	return imp.module + "." + imp.name + rest
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
	calleeText := strings.Join(strings.Fields(b.f.text(ctx, calleeNode)), "")
	calleeKind, _ := calleeNode.Kind(ctx)
	var argNodes []tswasm.Node
	argsText := ""
	if len(nc) > 1 {
		argNodes, _ = namedChildren(ctx, nc[1])
		argsText = b.f.text(ctx, nc[1])
	}

	if curFn >= 0 {
		canon := b.canonicalCallee(calleeText)
		var steps []chainStep
		root := ""
		if calleeKind == "attribute" {
			steps, root = flattenCallChain(ctx, b.f, n)
			if a, ok := matchDataAccess(ctx, b.f, steps, root); ok {
				b.p.stores.add(b.f.path, curFn, a)
			}
		}
		// true = self-blocking guard; false = a session read that only
		// counts if the function also refuses the request (see guards).
		if isGuardCall(calleeText) {
			b.directGuard[curFn] = b.directGuard[curFn] || isSelfBlockingGuard(calleeText)
		}
		if s, ok := pyKnownSinks[calleeText]; ok {
			b.addSink(ctx, n, curFn, calleeText, s.rule, s.sev)
		} else if s, ok := pyKnownSinks[canon]; ok {
			b.addSink(ctx, n, curFn, calleeText, s.rule, s.sev)
		} else if isServiceRoleClient(calleeText, argsText) {
			b.addSink(ctx, n, curFn, calleeText, ruleServiceRole, "medium")
		} else if pyHTTPClients[canon] && len(argNodes) > 0 {
			rule := "outbound HTTP request"
			if _, ok := literalString(ctx, b.f, argNodes[0]); !ok {
				rule = "outbound HTTP request to a computed URL (possible SSRF)"
			}
			b.addSink(ctx, n, curFn, calleeText, rule, "medium")
		} else if calleeKind == "attribute" {
			method := attrName(ctx, b.f, calleeNode)
			// supabase-py's query builder ends in .execute(); that is not
			// a DB-API cursor.
			if pySQLMethods[method] && !chainHasDataStep(steps) {
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
					b.addSink(ctx, n, curFn, calleeText, "SQL query built with string concatenation (injection)", "high")
				} else {
					b.addSink(ctx, n, curFn, calleeText, "SQL query execution", "medium")
				}
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

// recordImport reads `import a.b as c` and `from .x import y as z`.
func (b *pyBuilder) recordImport(ctx context.Context, n tswasm.Node, kind string) {
	nc, err := namedChildren(ctx, n)
	if err != nil || len(nc) == 0 {
		return
	}
	if kind == "import_statement" {
		for _, c := range nc {
			ck, _ := c.Kind(ctx)
			switch ck {
			case "dotted_name":
				mod := b.f.text(ctx, c)
				// `import a.b` binds `a`
				b.imports[strings.Split(mod, ".")[0]] = pyImport{module: strings.Split(mod, ".")[0]}
			case "aliased_import":
				cc, _ := namedChildren(ctx, c)
				if len(cc) == 2 {
					b.imports[b.f.text(ctx, cc[1])] = pyImport{module: b.f.text(ctx, cc[0])}
				}
			}
		}
		return
	}
	// import_from_statement: first child is the module (dotted_name or
	// relative_import), the rest are imported names.
	modNode := nc[0]
	module, level := "", 0
	if mk, _ := modNode.Kind(ctx); mk == "relative_import" {
		cc, _ := namedChildren(ctx, modNode)
		for _, c := range cc {
			switch k, _ := c.Kind(ctx); k {
			case "import_prefix":
				level = len(strings.TrimSpace(b.f.text(ctx, c)))
			case "dotted_name":
				module = b.f.text(ctx, c)
			}
		}
	} else {
		module = b.f.text(ctx, modNode)
	}
	for _, c := range nc[1:] {
		ck, _ := c.Kind(ctx)
		switch ck {
		case "dotted_name":
			name := b.f.text(ctx, c)
			b.imports[name] = pyImport{module: module, name: name, level: level}
		case "aliased_import":
			cc, _ := namedChildren(ctx, c)
			if len(cc) == 2 {
				b.imports[b.f.text(ctx, cc[1])] = pyImport{module: module, name: b.f.text(ctx, cc[0]), level: level}
			}
		}
	}
}
