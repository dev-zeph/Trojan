package graph

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/dev-zeph/trojan/internal/graph/tswasm"
)

// jsProject holds every file of one JS/TS batch so references can be
// resolved across files once all of them are walked.
type jsProject struct {
	g      *Graph
	mods   []*jsBuilder
	byAbs  map[string]*jsBuilder
	stores *storeTracker
	edges  map[[2]int]bool

	tsconfigs map[string]*tsPathConfig // dir -> nearest config (nil = none)
	roots     map[string]string        // dir -> nearest package.json dir
}

func newJSProject(g *Graph) *jsProject {
	p := &jsProject{
		g: g, byAbs: map[string]*jsBuilder{}, stores: newStoreTracker(g), edges: map[[2]int]bool{},
		tsconfigs: map[string]*tsPathConfig{}, roots: map[string]string{},
	}
	for _, e := range g.Edges {
		p.edges[[2]int{e.Src, e.Dst}] = true
	}
	return p
}

func (p *jsProject) add(b *jsBuilder) {
	p.mods = append(p.mods, b)
	p.byAbs[b.abs] = b
}

// link adds a call edge once.
func (p *jsProject) link(src, dst int) {
	if src == dst || src < 0 || dst < 0 {
		return
	}
	k := [2]int{src, dst}
	if p.edges[k] {
		return
	}
	p.edges[k] = true
	p.g.addEdge(src, dst, EdgeCalls)
}

// resolve runs the project pass: references, frameworks, guards, client
// boundary.
func (p *jsProject) resolve() {
	// Anonymous-callback edges were added during the walk; record them so
	// link() doesn't duplicate.
	for _, e := range p.g.Edges {
		if e.Kind == EdgeCalls {
			p.edges[[2]int{e.Src, e.Dst}] = true
		}
	}
	for _, b := range p.mods {
		p.resolveRefs(b)
	}
	direct := map[int]bool{}
	for _, b := range p.mods {
		for _, id := range b.guards() {
			direct[id] = true
		}
	}
	routeGuarded := map[int]bool{}
	p.resolveExpress(routeGuarded)
	nextRoutes, mws := p.resolveNext()
	p.markServerOnlyImports()

	// Guards first from function bodies, so a middleware.ts that calls
	// updateSession() -> supabase.auth.getUser() counts as auth middleware.
	propagateGuards(p.g, direct, routeGuarded)
	for _, mw := range mws {
		if !mw.auth && !(mw.fnID >= 0 && p.g.Nodes[mw.fnID].Guarded) {
			continue
		}
		for _, r := range nextRoutes {
			if r.root != mw.root {
				continue
			}
			if r.action && len(mw.prefixes) > 0 {
				continue // server actions post to page URLs we don't map
			}
			if len(mw.prefixes) == 0 || pathHasAnyPrefix(r.url, mw.prefixes) {
				routeGuarded[r.id] = true
			}
		}
	}
	propagateGuards(p.g, direct, routeGuarded)
}

// resolveRefs wires identifier and member references inside functions to
// the function or binding node they name, locally or through an import.
func (p *jsProject) resolveRefs(b *jsBuilder) {
	for _, fnID := range sortedKeys(b.refs) {
		for _, name := range sortedKeys(b.refs[fnID]) {
			if id, ok := b.byFunc[b.qualify(name)]; ok {
				p.link(fnID, id)
				continue
			}
			imp, ok := b.imports[name]
			if !ok || imp.name == "*" {
				continue
			}
			if m := p.resolveSpec(b, imp.spec); m != nil {
				if id := p.exportID(m, imp.name, 0); id >= 0 {
					p.link(fnID, id)
				}
			}
		}
	}
	for _, r := range b.memberRefs {
		imp := b.imports[r.local]
		m := p.resolveSpec(b, imp.spec)
		if m == nil {
			continue
		}
		if imp.name == "*" || imp.name == "default" {
			if id := p.exportID(m, r.key, 0); id >= 0 {
				p.link(r.fnID, id)
			}
		}
	}
}

// exportLocal follows a module's export table to the (module, local name)
// that defines an exported binding, through re-exports and barrels.
func (p *jsProject) exportLocal(m *jsBuilder, name string, depth int) (*jsBuilder, string) {
	if depth > 6 || m == nil {
		return nil, ""
	}
	if local, ok := m.exports[name]; ok {
		if _, defined := m.byFunc[m.qualify(local)]; defined {
			return m, local
		}
		if imp, ok := m.imports[local]; ok { // import { x } from "./a"; export { x }
			return p.exportLocal(p.resolveSpec(m, imp.spec), imp.name, depth+1)
		}
		return m, local
	}
	if imp, ok := m.reexports[name]; ok {
		return p.exportLocal(p.resolveSpec(m, imp.spec), imp.name, depth+1)
	}
	for _, spec := range m.starReexports {
		if mm, l := p.exportLocal(p.resolveSpec(m, spec), name, depth+1); mm != nil {
			return mm, l
		}
	}
	return nil, ""
}

// exportID is exportLocal resolved to a graph node, -1 if none.
func (p *jsProject) exportID(m *jsBuilder, name string, depth int) int {
	mm, local := p.exportLocal(m, name, depth)
	if mm == nil {
		return -1
	}
	if id, ok := mm.byFunc[mm.qualify(local)]; ok {
		return id
	}
	return -1
}

func isRelativeSpec(spec string) bool {
	return strings.HasPrefix(spec, "./") || strings.HasPrefix(spec, "../") || spec == "." || spec == ".."
}

var jsResolveExts = []string{"", ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".mts", ".cts"}

// resolveSpec maps an import specifier to a module of this batch: relative
// paths, tsconfig/jsconfig "paths" aliases ("@/lib/x") and baseUrl imports.
// Package imports ("express") resolve to nil.
func (p *jsProject) resolveSpec(from *jsBuilder, spec string) *jsBuilder {
	if spec == "" {
		return nil
	}
	var bases []string
	if isRelativeSpec(spec) {
		bases = append(bases, filepath.Join(filepath.Dir(from.abs), spec))
	} else if cfg := p.tsconfigFor(filepath.Dir(from.abs)); cfg != nil {
		bases = append(bases, cfg.candidates(spec)...)
	}
	for _, base := range bases {
		if m := p.lookupFile(base); m != nil {
			return m
		}
	}
	return nil
}

func (p *jsProject) lookupFile(base string) *jsBuilder {
	base = filepath.Clean(base)
	for _, ext := range jsResolveExts {
		if m, ok := p.byAbs[base+ext]; ok {
			return m
		}
	}
	for _, ext := range jsResolveExts[1:] {
		if m, ok := p.byAbs[filepath.Join(base, "index"+ext)]; ok {
			return m
		}
	}
	// TS ESM style: import "./x.js" that is really ./x.ts
	if ext := filepath.Ext(base); ext == ".js" || ext == ".jsx" || ext == ".mjs" {
		trimmed := strings.TrimSuffix(base, ext)
		for _, e := range []string{".ts", ".tsx", ".mts"} {
			if m, ok := p.byAbs[trimmed+e]; ok {
				return m
			}
		}
	}
	return nil
}

// tsPathConfig is the part of a tsconfig.json/jsconfig.json that affects
// module resolution.
type tsPathConfig struct {
	dir     string
	baseURL string // absolute; "" if unset
	paths   map[string][]string
}

// candidates expands a bare specifier through "paths" patterns (one "*"
// wildcard, TypeScript semantics) and baseUrl.
func (c *tsPathConfig) candidates(spec string) []string {
	root := c.baseURL
	if root == "" {
		root = c.dir
	}
	var out []string
	for pat, targets := range c.paths {
		star := strings.Index(pat, "*")
		matched, capture := false, ""
		if star < 0 {
			matched = pat == spec
		} else if pre, suf := pat[:star], pat[star+1:]; strings.HasPrefix(spec, pre) && strings.HasSuffix(spec, suf) && len(spec) >= len(pre)+len(suf) {
			matched, capture = true, spec[len(pre):len(spec)-len(suf)]
		}
		if !matched {
			continue
		}
		for _, t := range targets {
			out = append(out, filepath.Join(root, strings.Replace(t, "*", capture, 1)))
		}
	}
	if c.baseURL != "" {
		out = append(out, filepath.Join(c.baseURL, spec))
	}
	return out
}

// tsconfigFor returns the nearest tsconfig.json / jsconfig.json at or above
// dir (cached per directory). These config files are read from disk, not
// from the batch, so the incremental cache must hash them as inputs.
func (p *jsProject) tsconfigFor(dir string) *tsPathConfig {
	if c, ok := p.tsconfigs[dir]; ok {
		return c
	}
	var cfg *tsPathConfig
	for _, name := range []string{"tsconfig.json", "jsconfig.json"} {
		if c := loadTSConfig(filepath.Join(dir, name), 0); c != nil {
			cfg = c
			break
		}
	}
	if cfg == nil {
		parent := filepath.Dir(dir)
		if parent != dir {
			cfg = p.tsconfigFor(parent)
		}
	}
	p.tsconfigs[dir] = cfg
	return cfg
}

func loadTSConfig(path string, depth int) *tsPathConfig {
	raw, err := os.ReadFile(path)
	if err != nil || depth > 3 {
		return nil
	}
	var doc struct {
		Extends         any `json:"extends"`
		CompilerOptions struct {
			BaseURL string              `json:"baseUrl"`
			Paths   map[string][]string `json:"paths"`
		} `json:"compilerOptions"`
	}
	if err := json.Unmarshal(stripJSONC(raw), &doc); err != nil {
		return nil
	}
	dir := filepath.Dir(path)
	cfg := &tsPathConfig{dir: dir, paths: doc.CompilerOptions.Paths}
	if doc.CompilerOptions.BaseURL != "" {
		cfg.baseURL = filepath.Join(dir, doc.CompilerOptions.BaseURL)
	}
	if ext, ok := doc.Extends.(string); ok && isRelativeSpec(ext) {
		target := filepath.Join(dir, ext)
		if !strings.HasSuffix(target, ".json") {
			target += ".json"
		}
		if parent := loadTSConfig(target, depth+1); parent != nil {
			if cfg.paths == nil {
				cfg.paths = parent.paths
				if cfg.baseURL == "" {
					cfg.baseURL = parent.baseURL
				}
				cfg.dir = parent.dir
			}
			if cfg.baseURL == "" {
				cfg.baseURL = parent.baseURL
			}
		}
	}
	return cfg
}

// stripJSONC removes // and /* */ comments (outside strings) and trailing
// commas, since tsconfig.json is JSON-with-comments.
func stripJSONC(in []byte) []byte {
	var out []byte
	inStr, esc := false, false
	for i := 0; i < len(in); i++ {
		c := in[i]
		if inStr {
			out = append(out, c)
			switch {
			case esc:
				esc = false
			case c == '\\':
				esc = true
			case c == '"':
				inStr = false
			}
			continue
		}
		if c == '"' {
			inStr = true
			out = append(out, c)
			continue
		}
		if c == '/' && i+1 < len(in) && in[i+1] == '/' {
			for i < len(in) && in[i] != '\n' {
				i++
			}
			continue
		}
		if c == '/' && i+1 < len(in) && in[i+1] == '*' {
			i += 2
			for i+1 < len(in) && !(in[i] == '*' && in[i+1] == '/') {
				i++
			}
			i++
			continue
		}
		out = append(out, c)
	}
	// trailing commas
	var res []byte
	for i := 0; i < len(out); i++ {
		if out[i] == ',' {
			j := i + 1
			for j < len(out) && (out[j] == ' ' || out[j] == '\n' || out[j] == '\r' || out[j] == '\t') {
				j++
			}
			if j < len(out) && (out[j] == '}' || out[j] == ']') {
				continue
			}
		}
		res = append(res, out[i])
	}
	return res
}

// projectRoot returns the nearest directory at or above dir holding a
// package.json (cached), or dir itself if none.
func (p *jsProject) projectRoot(dir string) string {
	if r, ok := p.roots[dir]; ok {
		return r
	}
	root := dir
	for d := dir; ; {
		if fileExists(filepath.Join(d, "package.json")) {
			root = d
			break
		}
		parent := filepath.Dir(d)
		if parent == d {
			break
		}
		d = parent
	}
	p.roots[dir] = root
	return root
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// prepass reads the module-level shape of a file before the main walk:
// directive prologue, imports, exports. Sink canonicalization during the walk
// needs imports, and ClientSide needs the directive.
func (b *jsBuilder) prepass(ctx context.Context, root tswasm.Node) {
	b.directive = firstDirective(ctx, b.f, root)
	stmts, err := namedChildren(ctx, root)
	if err != nil {
		return
	}
	for _, s := range stmts {
		k, _ := s.Kind(ctx)
		switch k {
		case "import_statement":
			b.recordImport(ctx, s)
		case "export_statement":
			b.recordExport(ctx, s)
		case "expression_statement":
			if e, ok := firstNamedChild(ctx, s); ok {
				if ek, _ := e.Kind(ctx); ek == "assignment_expression" {
					b.recordCJSExport(ctx, e)
				} else if ek == "call_expression" {
					// require("server-only") side-effect import
					if spec, ok := b.requireSpec(ctx, e); ok && isServerOnlySpec(spec) {
						b.serverOnly = true
					}
				}
			}
		}
	}
}

func isServerOnlySpec(spec string) bool {
	return spec == "server-only" || spec == "next/headers"
}

func (b *jsBuilder) recordImport(ctx context.Context, s tswasm.Node) {
	nc, err := namedChildren(ctx, s)
	if err != nil {
		return
	}
	spec := ""
	for _, c := range nc {
		if v, ok := literalString(ctx, b.f, c); ok {
			spec = v
		}
	}
	if isServerOnlySpec(spec) {
		b.serverOnly = true
	}
	clause, ok := findByKind(ctx, nc, map[string]bool{"import_clause": true})
	if !ok {
		return
	}
	parts, _ := namedChildren(ctx, clause)
	for _, part := range parts {
		pk, _ := part.Kind(ctx)
		switch pk {
		case "identifier":
			b.imports[b.f.text(ctx, part)] = jsImport{spec: spec, name: "default"}
		case "namespace_import":
			if id, ok := firstNamedChild(ctx, part); ok {
				b.imports[b.f.text(ctx, id)] = jsImport{spec: spec, name: "*"}
			}
		case "named_imports":
			specs, _ := namedChildren(ctx, part)
			for _, is := range specs {
				ids, _ := namedChildren(ctx, is)
				if len(ids) == 0 {
					continue
				}
				name := b.f.text(ctx, ids[0])
				local := b.f.text(ctx, ids[len(ids)-1])
				b.imports[local] = jsImport{spec: spec, name: name}
			}
		}
	}
}

func (b *jsBuilder) recordExport(ctx context.Context, s tswasm.Node) {
	kids, _ := allChildren(ctx, s)
	isDefault := false
	for _, k := range kids {
		if kk, _ := k.Kind(ctx); kk == "default" {
			isDefault = true
		}
	}
	nc, _ := namedChildren(ctx, s)
	spec := ""
	for _, c := range nc {
		if ck, _ := c.Kind(ctx); ck == "string" {
			spec, _ = literalString(ctx, b.f, c)
		}
	}
	for _, c := range nc {
		ck, _ := c.Kind(ctx)
		switch ck {
		case "function_declaration", "generator_function_declaration", "class_declaration":
			cc, _ := namedChildren(ctx, c)
			if id, ok := findByKind(ctx, cc, map[string]bool{"identifier": true, "type_identifier": true}); ok {
				name := b.f.text(ctx, id)
				b.exports[name] = name
				if isDefault {
					b.exports["default"] = name
				}
			}
		case "lexical_declaration", "variable_declaration":
			decls, _ := namedChildren(ctx, c)
			for _, d := range decls {
				if id, ok := firstNamedChild(ctx, d); ok {
					if ik, _ := id.Kind(ctx); ik == "identifier" {
						name := b.f.text(ctx, id)
						b.exports[name] = name
					}
				}
			}
		case "export_clause":
			specs, _ := namedChildren(ctx, c)
			for _, es := range specs {
				ids, _ := namedChildren(ctx, es)
				if len(ids) == 0 {
					continue
				}
				local := b.f.text(ctx, ids[0])
				exported := b.f.text(ctx, ids[len(ids)-1])
				if spec != "" {
					b.reexports[exported] = jsImport{spec: spec, name: local}
				} else {
					b.exports[exported] = local
				}
			}
		case "identifier":
			if isDefault {
				b.exports["default"] = b.f.text(ctx, c)
			}
		}
	}
	if spec != "" {
		hasClause := false
		for _, c := range nc {
			if ck, _ := c.Kind(ctx); ck == "export_clause" || ck == "namespace_export" {
				hasClause = true
			}
		}
		if !hasClause {
			b.starReexports = append(b.starReexports, spec)
		}
	}
}

// cjsExportName returns the exported name for a CommonJS export target:
// "module.exports" -> "default", "exports.foo"/"module.exports.foo" -> "foo".
func cjsExportName(left string) string {
	left = strings.Join(strings.Fields(left), "")
	switch {
	case left == "module.exports":
		return "default"
	case strings.HasPrefix(left, "module.exports."):
		return strings.TrimPrefix(left, "module.exports.")
	case strings.HasPrefix(left, "exports."):
		return strings.TrimPrefix(left, "exports.")
	}
	return ""
}

// recordCJSExport reads module.exports = X / { a, b: c } and exports.x = y.
// (Function-valued exports are named and registered by walk.)
func (b *jsBuilder) recordCJSExport(ctx context.Context, assign tswasm.Node) {
	nc, err := namedChildren(ctx, assign)
	if err != nil || len(nc) < 2 {
		return
	}
	name := cjsExportName(b.f.text(ctx, nc[0]))
	if name == "" {
		return
	}
	right := nc[len(nc)-1]
	rk, _ := right.Kind(ctx)
	switch rk {
	case "identifier":
		b.exports[name] = b.f.text(ctx, right)
	case "object":
		if name != "default" {
			return
		}
		props, _ := namedChildren(ctx, right)
		for _, pr := range props {
			pk, _ := pr.Kind(ctx)
			switch pk {
			case "shorthand_property_identifier":
				v := b.f.text(ctx, pr)
				b.exports[v] = v
			case "pair":
				kv, _ := namedChildren(ctx, pr)
				if len(kv) == 2 {
					if vk, _ := kv[1].Kind(ctx); vk == "identifier" {
						b.exports[b.f.text(ctx, kv[0])] = b.f.text(ctx, kv[1])
					}
				}
			}
		}
	}
}

// requireSpec returns the module of a require("x") call (or require("x").y
// is handled by the caller).
func (b *jsBuilder) requireSpec(ctx context.Context, n tswasm.Node) (string, bool) {
	k, _ := n.Kind(ctx)
	if k != "call_expression" {
		return "", false
	}
	nc, err := namedChildren(ctx, n)
	if err != nil || len(nc) < 2 || b.f.text(ctx, nc[0]) != "require" {
		return "", false
	}
	args, _ := namedChildren(ctx, nc[1])
	if len(args) == 0 {
		return "", false
	}
	return literalString(ctx, b.f, args[0])
}

func (b *jsBuilder) isRequireCall(ctx context.Context, n tswasm.Node) bool {
	if _, ok := b.requireSpec(ctx, n); ok {
		return true
	}
	// require("x").y
	if k, _ := n.Kind(ctx); k == "member_expression" {
		if obj, ok := firstNamedChild(ctx, n); ok {
			_, isReq := b.requireSpec(ctx, obj)
			return isReq
		}
	}
	return false
}

// recordRequire records CommonJS imports from a declarator:
// const x = require("m"); const { a, b: c } = require("m");
// const y = require("m").y.
func (b *jsBuilder) recordRequire(ctx context.Context, nameNode, value tswasm.Node) {
	spec, ok := b.requireSpec(ctx, value)
	member := ""
	if !ok {
		if k, _ := value.Kind(ctx); k == "member_expression" {
			if nc, err := namedChildren(ctx, value); err == nil && len(nc) == 2 {
				if spec, ok = b.requireSpec(ctx, nc[0]); ok {
					member = b.f.text(ctx, nc[1])
				}
			}
		}
		if !ok {
			return
		}
	}
	if isServerOnlySpec(spec) {
		b.serverOnly = true
	}
	nk, _ := nameNode.Kind(ctx)
	switch nk {
	case "identifier":
		name := "default"
		if member != "" {
			name = member
		}
		b.imports[b.f.text(ctx, nameNode)] = jsImport{spec: spec, name: name}
	case "object_pattern":
		props, _ := namedChildren(ctx, nameNode)
		for _, pr := range props {
			pk, _ := pr.Kind(ctx)
			switch pk {
			case "shorthand_property_identifier_pattern":
				v := b.f.text(ctx, pr)
				b.imports[v] = jsImport{spec: spec, name: v}
			case "pair_pattern":
				kv, _ := namedChildren(ctx, pr)
				if len(kv) == 2 {
					b.imports[b.f.text(ctx, kv[1])] = jsImport{spec: spec, name: b.f.text(ctx, kv[0])}
				}
			}
		}
	}
}

// markServerOnlyImports adds a high-severity sink inside every client-side
// function that references an import of a server-only module (one that
// imports "server-only" or next/headers), so ClientExposures reports it.
func (p *jsProject) markServerOnlyImports() {
	for _, b := range p.mods {
		if b.directive != "use client" {
			continue
		}
		for _, fnID := range sortedKeys(b.refs) {
			for _, name := range sortedKeys(b.refs[fnID]) {
				imp, ok := b.imports[name]
				if !ok {
					continue
				}
				m := p.resolveSpec(b, imp.spec)
				if m == nil || !m.serverOnly {
					continue
				}
				id := p.g.addNode(Node{
					Kind: KindSink, Name: name, File: b.f.path, Line: p.g.Nodes[fnID].Line,
					SinkRule: ruleServerOnly, Severity: "high", ClientSide: true,
				})
				p.g.addEdge(fnID, id, EdgeContains)
			}
		}
	}
}

// sortedKeys returns a map's keys in order, so graph construction is
// deterministic (same input, same node and edge order).
func sortedKeys[K int | string, V any](m map[K]V) []K {
	out := make([]K, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
