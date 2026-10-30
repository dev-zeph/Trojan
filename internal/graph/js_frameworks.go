package graph

import (
	"path"
	"path/filepath"
	"regexp"
	"strings"
)

// Framework entrypoints for JS/TS: Express-style routers (including routers
// mounted from other files) and Next.js (app router route handlers, pages/api,
// server actions, middleware.ts and its matcher).

// expressMount is one app.use(prefix, router) edge, seen from the router.
type expressMount struct {
	from     *jsBuilder
	fromRecv string
	prefix   string
	guarded  bool // auth middleware ahead of the router in this mount
}

// mountTarget resolves a use() argument to the (module, local binding) it
// names, if that binding is an Express router.
func (p *jsProject) mountTarget(b *jsBuilder, a jsUseArg) (*jsBuilder, string, bool) {
	var m *jsBuilder
	local := ""
	switch {
	case a.spec != "":
		m, local = p.exportLocal(p.resolveSpec(b, a.spec), "default", 0)
	case a.name != "":
		if _, ok := b.bindings[a.name]; ok {
			m, local = b, a.name
		} else if imp, ok := b.imports[a.name]; ok {
			m, local = p.exportLocal(p.resolveSpec(b, imp.spec), imp.name, 0)
		}
	}
	if m == nil || local == "" {
		return nil, "", false
	}
	for _, r := range m.routes {
		if r.receiver == local {
			return m, local, true
		}
	}
	for _, u := range m.uses {
		if u.receiver == local {
			return m, local, true
		}
	}
	if init, ok := m.bindings[local]; ok && strings.Contains(init, "Router") {
		return m, local, true
	}
	return nil, "", false
}

// precedingAuthUse reports whether receiver.use(authMiddleware) runs before
// pos in b for a path under its prefix.
func (p *jsProject) precedingAuthUse(b *jsBuilder, receiver, routePath string, pos uint32) bool {
	for _, u := range b.uses {
		if u.receiver != receiver || u.pos >= pos {
			continue
		}
		if u.prefix != "" && !pathHasAnyPrefix(routePath, []string{u.prefix}) {
			continue
		}
		for _, a := range u.args {
			if _, _, isRouter := p.mountTarget(b, a); !isRouter && isAuthLikeName(a.name) {
				return true
			}
		}
	}
	return false
}

type mountPath struct {
	prefix  string
	guarded bool
}

// resolveExpress marks Express route handlers as sources, names inline
// handlers by method and full mounted path ("GET /api/users/:id"), and
// records which routes sit behind auth middleware.
func (p *jsProject) resolveExpress(routeGuarded map[int]bool) {
	index := map[string][]expressMount{}
	for _, b := range p.mods {
		for _, u := range b.uses {
			for i, a := range u.args {
				m, local, ok := p.mountTarget(b, a)
				if !ok {
					continue
				}
				guarded := p.precedingAuthUse(b, u.receiver, u.prefix, u.pos)
				for _, prev := range u.args[:i] {
					if _, _, isRouter := p.mountTarget(b, prev); !isRouter && isAuthLikeName(prev.name) {
						guarded = true
					}
				}
				key := m.abs + "|" + local
				index[key] = append(index[key], expressMount{from: b, fromRecv: u.receiver, prefix: u.prefix, guarded: guarded})
			}
		}
	}

	var mountsOf func(m *jsBuilder, recv string, depth int) []mountPath
	mountsOf = func(m *jsBuilder, recv string, depth int) []mountPath {
		ms := index[m.abs+"|"+recv]
		if len(ms) == 0 || depth > 6 {
			return []mountPath{{}}
		}
		var out []mountPath
		for _, mt := range ms {
			for _, parent := range mountsOf(mt.from, mt.fromRecv, depth+1) {
				out = append(out, mountPath{
					prefix:  joinURLPath(parent.prefix, mt.prefix),
					guarded: parent.guarded || mt.guarded,
				})
			}
		}
		return out
	}

	seen := map[int]bool{}
	for _, b := range p.mods {
		for _, r := range b.routes {
			id := r.handlerID
			if id < 0 {
				id = p.resolveHandlerRef(b, r.handlerRef)
			}
			if id < 0 {
				continue
			}
			mounts := mountsOf(b, r.receiver, 0)
			routeMW := false
			for _, mw := range r.middleware {
				if isAuthLikeName(mw) {
					routeMW = true
				}
			}
			guarded := true
			if !routeMW {
				for _, mt := range mounts {
					if !mt.guarded && !p.precedingAuthUse(b, r.receiver, r.path, r.pos) {
						guarded = false
					}
				}
			}
			p.g.Nodes[id].Source = true
			if prev, ok := routeGuarded[id]; ok && seen[id] {
				guarded = guarded && prev
			}
			seen[id] = true
			routeGuarded[id] = guarded
			if r.handlerID >= 0 {
				p.g.Nodes[id].Name = b.qualify(r.method + " " + joinURLPath(mounts[0].prefix, r.path))
			}
		}
	}
}

// resolveHandlerRef resolves a by-reference route handler: a local function,
// an imported one, or ns.fn on an imported module (controllers.getUser).
func (p *jsProject) resolveHandlerRef(b *jsBuilder, ref string) int {
	if ref == "" {
		return -1
	}
	if id, ok := b.byFunc[b.qualify(ref)]; ok {
		return id
	}
	head, rest := ref, ""
	if i := strings.Index(ref, "."); i >= 0 {
		head, rest = ref[:i], ref[i+1:]
	}
	imp, ok := b.imports[head]
	if !ok {
		return -1
	}
	m := p.resolveSpec(b, imp.spec)
	if m == nil {
		return -1
	}
	if rest == "" {
		return p.exportID(m, imp.name, 0)
	}
	if imp.name == "default" || imp.name == "*" {
		return p.exportID(m, rest, 0)
	}
	return -1
}

func joinURLPath(prefix, p string) string {
	if prefix == "" || prefix == "/" {
		if p == "" {
			return "/"
		}
		return p
	}
	if p == "" || p == "/" {
		return prefix
	}
	return strings.TrimSuffix(prefix, "/") + "/" + strings.TrimPrefix(p, "/")
}

// pathHasAnyPrefix reports whether routePath falls under one of the
// prefixes (same semantics as internal/routes).
func pathHasAnyPrefix(routePath string, prefixes []string) bool {
	for _, p := range prefixes {
		if p == "/" || routePath == p || strings.HasPrefix(routePath, strings.TrimSuffix(p, "/")+"/") {
			return true
		}
	}
	return false
}

// nextRoute is a Next.js entrypoint with its URL, for middleware coverage.
type nextRoute struct {
	id     int
	url    string
	root   string
	action bool // server action (POSTs to a page URL we don't map)
}

// nextMiddleware is a middleware.ts (or Next 16 proxy.ts) file.
type nextMiddleware struct {
	root     string
	fnID     int
	prefixes []string // nil = matches every route
	auth     bool     // re-exports or configures an auth middleware
}

var nextHTTPMethods = []string{"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}

// resolveNext marks Next.js entrypoints as sources and collects middleware.
// The project root is the nearest package.json directory above each file.
func (p *jsProject) resolveNext() ([]nextRoute, []nextMiddleware) {
	var routes []nextRoute
	var mws []nextMiddleware
	for _, b := range p.mods {
		root := p.projectRoot(filepath.Dir(b.abs))
		rel, err := filepath.Rel(root, b.abs)
		if err != nil {
			continue
		}
		rel = filepath.ToSlash(rel)
		stem := strings.TrimSuffix(path.Base(rel), path.Ext(rel))
		mark := func(id int, url string, action bool) {
			p.g.Nodes[id].Source = true
			routes = append(routes, nextRoute{id: id, url: url, root: root, action: action})
		}

		for _, appDir := range []string{"app/", "src/app/"} {
			if !strings.HasPrefix(rel, appDir) || stem != "route" {
				continue
			}
			url, ok := nextURLPath(path.Dir(strings.TrimPrefix(rel, appDir)))
			if !ok {
				continue
			}
			for _, m := range nextHTTPMethods {
				if id := p.exportID(b, m, 0); id >= 0 {
					mark(id, url, false)
				}
			}
		}
		for _, pagesAPI := range []string{"pages/api/", "src/pages/api/"} {
			if !strings.HasPrefix(rel, pagesAPI) {
				continue
			}
			sub := strings.TrimSuffix(strings.TrimPrefix(rel, "pages/"), path.Ext(rel))
			sub = strings.TrimPrefix(sub, "src/pages/")
			sub = strings.TrimSuffix(strings.TrimSuffix(sub, "/index"), "index")
			url, _ := nextURLPath(sub)
			if id := p.exportID(b, "default", 0); id >= 0 {
				mark(id, url, false)
			}
		}
		if b.directive == "use server" {
			for _, name := range sortedKeys(b.exports) {
				if id := p.exportID(b, name, 0); id >= 0 && p.g.Nodes[id].Kind == KindFunc {
					mark(id, "", true)
				}
			}
		}
		for _, id := range b.inlineActions {
			mark(id, "", true)
		}

		switch rel {
		case "middleware.ts", "middleware.js", "src/middleware.ts", "src/middleware.js",
			"proxy.ts", "proxy.js", "src/proxy.ts", "src/proxy.js":
			mw := nextMiddleware{root: root, fnID: -1}
			for _, name := range []string{"middleware", "proxy", "default"} {
				if id := p.exportID(b, name, 0); id >= 0 {
					mw.fnID = id
					p.g.Nodes[id].Source = true
					break
				}
			}
			text := string(b.f.src)
			mw.prefixes = middlewareMatcherPrefixes(text)
			mw.auth = strings.Contains(text, "next-auth/middleware") || strings.Contains(text, ".protect(")
			mws = append(mws, mw)
		}
	}
	return routes, mws
}

// nextURLPath converts a Next.js route directory (relative to app/ or
// pages/) into a URL pattern; mirrors internal/routes. Route groups (x) and
// slots @x are dropped; a private folder _x is not routable.
func nextURLPath(relDir string) (string, bool) {
	if relDir == "." || relDir == "" {
		return "/", true
	}
	var out []string
	for _, seg := range strings.Split(relDir, "/") {
		switch {
		case seg == "" || seg == ".":
			continue
		case strings.HasPrefix(seg, "_"):
			return "", false
		case strings.HasPrefix(seg, "(") && strings.HasSuffix(seg, ")"), strings.HasPrefix(seg, "@"):
			continue
		case strings.HasPrefix(seg, "[") && strings.HasSuffix(seg, "]"):
			name := strings.Trim(seg, "[].")
			out = append(out, "{"+name+"}")
		default:
			out = append(out, seg)
		}
	}
	if len(out) == 0 {
		return "/", true
	}
	return "/" + strings.Join(out, "/"), true
}

var (
	matcherBlockRe = regexp.MustCompile(`matcher\s*:\s*(\[[^\]]*\]|['"` + "`" + `][^'"` + "`" + `]*['"` + "`" + `])`)
	matcherStrRe   = regexp.MustCompile(`['"` + "`" + `]([^'"` + "`" + `]+)['"` + "`" + `]`)
)

// middlewareMatcherPrefixes extracts literal path prefixes from a middleware
// config.matcher ('/dashboard/:path*' -> '/dashboard'); nil when there is no
// matcher, meaning the middleware runs on every route. Mirrors
// internal/routes.
func middlewareMatcherPrefixes(content string) []string {
	block := matcherBlockRe.FindStringSubmatch(content)
	if block == nil {
		return nil
	}
	var prefixes []string
	for _, m := range matcherStrRe.FindAllStringSubmatch(block[1], -1) {
		pat := m[1]
		if i := strings.IndexAny(pat, ":*?(["); i >= 0 {
			pat = pat[:i]
		}
		prefixes = append(prefixes, "/"+strings.Trim(pat, "/"))
	}
	return prefixes
}
