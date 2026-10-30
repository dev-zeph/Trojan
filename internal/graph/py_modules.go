package graph

import (
	"path/filepath"
	"strings"
)

// pyProject holds every file of one Python batch for cross-file resolution.
type pyProject struct {
	g      *Graph
	mods   []*pyBuilder
	byAbs  map[string]*pyBuilder
	stores *storeTracker
	edges  map[[2]int]bool
}

func newPyProject(g *Graph) *pyProject {
	return &pyProject{g: g, byAbs: map[string]*pyBuilder{}, stores: newStoreTracker(g), edges: map[[2]int]bool{}}
}

func (p *pyProject) add(b *pyBuilder) {
	p.mods = append(p.mods, b)
	p.byAbs[b.abs] = b
}

func (p *pyProject) link(src, dst int) {
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

// resolve wires references (same file first, then imports) and finishes
// guards.
func (p *pyProject) resolve() {
	direct := map[int]bool{}
	routeGuarded := map[int]bool{}
	for _, b := range p.mods {
		for _, fnID := range sortedKeys(b.refs) {
			for _, name := range sortedKeys(b.refs[fnID]) {
				if id, ok := b.byFunc[b.qualify(name)]; ok {
					p.link(fnID, id)
					continue
				}
				imp, ok := b.imports[name]
				if !ok {
					continue
				}
				if id := p.importID(b, imp); id >= 0 {
					p.link(fnID, id)
				}
			}
		}
		for _, r := range b.memberRefs {
			imp := b.imports[r.local]
			// `import db` / `from pkg import db` (a module): db.attr
			if m := p.importedModule(b, imp); m != nil {
				if id := p.nameID(m, r.attr, 0); id >= 0 {
					p.link(r.fnID, id)
				}
			}
		}
		for _, id := range b.guards() {
			direct[id] = true
		}
		for id := range b.routeGuard {
			routeGuarded[id] = true
		}
	}
	for _, b := range p.mods {
		for dep := range b.dependencies {
			id, ok := b.byFunc[b.qualify(dep)]
			if !ok {
				if imp, isImp := b.imports[dep]; isImp {
					id = p.importID(b, imp)
				} else {
					id = -1
				}
			}
			if id >= 0 {
				for _, m := range p.mods {
					if m.heuristicSource[id] {
						p.g.Nodes[id].Source = false
					}
				}
			}
		}
	}
	propagateGuards(p.g, direct, routeGuarded)
}

// importID resolves `from mod import name` to the node defining name.
func (p *pyProject) importID(b *pyBuilder, imp pyImport) int {
	if imp.name == "" {
		return -1
	}
	if m := p.findModule(b, imp.module, imp.level); m != nil {
		return p.nameID(m, imp.name, 0)
	}
	return -1
}

// importedModule returns the module an import binds when it binds a module
// rather than a name: `import db`, `import pkg.db as db`, `from pkg import db`.
func (p *pyProject) importedModule(b *pyBuilder, imp pyImport) *pyBuilder {
	if imp.name == "" {
		return p.findModule(b, imp.module, imp.level)
	}
	sub := imp.name
	if imp.module != "" {
		sub = imp.module + "." + imp.name
	}
	return p.findModule(b, sub, imp.level)
}

// nameID finds a top-level function or binding in m, following re-exports
// (`from .db import get_conn` in a package __init__.py).
func (p *pyProject) nameID(m *pyBuilder, name string, depth int) int {
	if id, ok := m.byFunc[m.qualify(name)]; ok {
		return id
	}
	if depth > 4 {
		return -1
	}
	if imp, ok := m.imports[name]; ok {
		if mm := p.findModule(m, imp.module, imp.level); mm != nil && imp.name != "" {
			return p.nameID(mm, imp.name, depth+1)
		}
	}
	return -1
}

// findModule resolves a dotted module name to a file of this batch. Absolute
// imports are tried against the importing file's directory and each of its
// ancestors (covering both "run from project root" and package layouts);
// relative imports start level-1 directories above the importer.
func (p *pyProject) findModule(from *pyBuilder, module string, level int) *pyBuilder {
	rel := filepath.FromSlash(strings.ReplaceAll(module, ".", "/"))
	try := func(dir string) *pyBuilder {
		base := filepath.Join(dir, rel)
		if module == "" {
			base = dir
		}
		if m, ok := p.byAbs[base+".py"]; ok && module != "" {
			return m
		}
		if m, ok := p.byAbs[filepath.Join(base, "__init__.py")]; ok {
			return m
		}
		return nil
	}
	dir := filepath.Dir(from.abs)
	if level > 0 {
		for i := 1; i < level; i++ {
			dir = filepath.Dir(dir)
		}
		return try(dir)
	}
	for i := 0; i < 6; i++ {
		if m := try(dir); m != nil && m != from {
			return m
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return nil
}
