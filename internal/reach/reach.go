// Package reach places code findings in Trojan's code graph. For a finding at
// file:line it finds the enclosing function, then answers the questions that
// decide how urgent the finding is: can a public entrypoint reach this code,
// is every such path behind an auth check, which datastores does it read or
// write, does it touch sensitive data, and does it run in the browser.
//
// The same Analyzer backs the MCP graph tools (internal/mcpserver), so a
// finding's reach fields and what get_attack_paths reports always agree.
package reach

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/dev-zeph/trojan/internal/graph"
	"github.com/dev-zeph/trojan/internal/graphstore"
	"github.com/dev-zeph/trojan/internal/normalizer"
	"github.com/dev-zeph/trojan/internal/orgcontext"
)

// LoadGraph brings the project's persisted graph (.trojan/graph.db) up to
// date and layers .trojan/context.yaml onto it. graphstore.Refresh does not
// keep org-context tags, so the overlay is re-applied on every load. The
// returned context is nil when the project has none (or it doesn't parse;
// the graph is still useful without it).
func LoadGraph(projectRoot string) (*graph.Graph, *orgcontext.OrgContext, error) {
	g, _, err := graphstore.Refresh(projectRoot)
	if err != nil {
		return nil, nil, err
	}
	var ctx *orgcontext.OrgContext
	if p := orgcontext.Path(projectRoot); orgcontext.Exists(p) {
		if loaded, err := orgcontext.Load(p); err == nil {
			ctx = loaded
			orgcontext.ApplyOverlay(g, ctx)
		}
	}
	return g, ctx, nil
}

// Enrich refreshes the project's graph, attaches ReachInfo to every finding
// it can place, and ranks the findings (see Rank). Callers in the scan path
// log a returned error and keep the scan: reach data is additive.
func Enrich(projectRoot string, findings []normalizer.Finding) error {
	g, _, err := LoadGraph(projectRoot)
	if err != nil {
		return fmt.Errorf("reach: %w", err)
	}
	New(g, projectRoot).Annotate(findings)
	Rank(findings)
	return nil
}

// Rank stable-sorts findings by Reach.Priority, highest first: exposed and
// sensitive code ahead of the rest. Findings without reach data keep their
// relative order after placed ones of priority > 0.
func Rank(findings []normalizer.Finding) {
	sort.SliceStable(findings, func(i, j int) bool {
		return priority(findings[i]) > priority(findings[j])
	})
}

func priority(f normalizer.Finding) int {
	if f.Reach == nil {
		return 0
	}
	return f.Reach.Priority
}

// Analyzer answers reachability questions over one graph. Construction does
// all the graph walks once, so per-finding lookups are cheap.
type Analyzer struct {
	G    *graph.Graph
	Root string

	calls    map[int][]int
	callers  map[int][]int
	access   map[int][]graph.Edge // func -> contains/reads/writes edges
	byFile   map[string][]int     // rel path -> func IDs sorted by line
	entries  map[int][]int        // func -> entrypoints reaching it (capped)
	unguard  map[int][]int        // func -> unguarded entrypoints reaching it without crossing a guard (capped)
	client   map[int]bool         // reached from browser code
	srcLines map[string][]string  // cache for route labels
}

// maxEntriesPerFunc caps the entrypoint lists kept per function. Flags
// (reachable, unguarded) stay exact; only the listed examples are capped.
const maxEntriesPerFunc = 5

// New indexes g for reachability queries. root is the project root, used to
// turn absolute node and finding paths into project-relative ones.
func New(g *graph.Graph, root string) *Analyzer {
	if abs, err := filepath.Abs(root); err == nil {
		root = abs
	}
	a := &Analyzer{
		G: g, Root: root,
		calls:    map[int][]int{},
		callers:  map[int][]int{},
		access:   map[int][]graph.Edge{},
		byFile:   map[string][]int{},
		entries:  map[int][]int{},
		unguard:  map[int][]int{},
		client:   map[int]bool{},
		srcLines: map[string][]string{},
	}
	for _, e := range g.Edges {
		switch e.Kind {
		case graph.EdgeCalls:
			a.calls[e.Src] = append(a.calls[e.Src], e.Dst)
			a.callers[e.Dst] = append(a.callers[e.Dst], e.Src)
		case graph.EdgeContains, graph.EdgeReads, graph.EdgeWrites:
			a.access[e.Src] = append(a.access[e.Src], e)
		}
	}
	for _, n := range g.Nodes {
		if n.Kind == graph.KindFunc {
			rel := a.Rel(n.File)
			a.byFile[rel] = append(a.byFile[rel], n.ID)
		}
	}
	for f, ids := range a.byFile {
		sort.Slice(ids, func(i, j int) bool { return g.Nodes[ids[i]].Line < g.Nodes[ids[j]].Line })
		a.byFile[f] = ids
	}
	for _, n := range g.Nodes {
		if n.Kind != graph.KindFunc {
			continue
		}
		if n.Source {
			a.walk(n.ID, false, func(id int) { a.entries[id] = appendCapped(a.entries[id], n.ID) })
			if !n.Guarded {
				a.walk(n.ID, true, func(id int) { a.unguard[id] = appendCapped(a.unguard[id], n.ID) })
			}
		}
		if n.ClientSide {
			a.walk(n.ID, false, func(id int) { a.client[id] = true })
		}
	}
	return a
}

// appendCapped records an entrypoint for a function. The list is capped, but
// a non-empty list is what the flags test, so they stay exact.
func appendCapped(list []int, id int) []int {
	if len(list) >= maxEntriesPerFunc {
		return list
	}
	return append(list, id)
}

// walk visits every function reachable from start over call edges (start
// included). With skipGuarded it never enters a Guarded function, which is
// how "reachable without passing an auth check" is computed.
func (a *Analyzer) walk(start int, skipGuarded bool, visit func(int)) {
	seen := map[int]bool{start: true}
	queue := []int{start}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		visit(cur)
		for _, next := range a.calls[cur] {
			if seen[next] || (skipGuarded && a.G.Nodes[next].Guarded) {
				continue
			}
			seen[next] = true
			queue = append(queue, next)
		}
	}
}

// Rel returns p relative to the project root with forward slashes.
func (a *Analyzer) Rel(p string) string {
	if filepath.IsAbs(p) {
		if r, err := filepath.Rel(a.Root, p); err == nil {
			return filepath.ToSlash(r)
		}
	}
	return filepath.ToSlash(filepath.Clean(p))
}

// Loc renders a node as "relpath:line".
func (a *Analyzer) Loc(n graph.Node) string {
	return fmt.Sprintf("%s:%d", a.Rel(n.File), n.Line)
}

// Enclosing returns the function containing file:line: the nearest function
// in the same file that starts at or above the line. A file path that doesn't
// match exactly is matched by suffix, since scanners report paths relative to
// wherever they were run.
func (a *Analyzer) Enclosing(file string, line int) (graph.Node, bool) {
	if line <= 0 || file == "" {
		return graph.Node{}, false
	}
	ids := a.funcsIn(a.Rel(file))
	best := -1
	for _, id := range ids {
		if a.G.Nodes[id].Line <= line {
			best = id
		} else {
			break
		}
	}
	if best < 0 {
		return graph.Node{}, false
	}
	return a.G.Nodes[best], true
}

func (a *Analyzer) funcsIn(rel string) []int {
	if ids, ok := a.byFile[rel]; ok {
		return ids
	}
	var match string
	for f := range a.byFile {
		if (strings.HasSuffix(rel, "/"+f) || strings.HasSuffix(f, "/"+rel)) && len(f) > len(match) {
			match = f
		}
	}
	return a.byFile[match]
}

// Annotate sets Reach on every finding the graph can place.
func (a *Analyzer) Annotate(findings []normalizer.Finding) {
	for i := range findings {
		findings[i].Reach = a.ForLocation(findings[i].FilePath, findings[i].LineNumber)
	}
}

// ForLocation returns reach data for the function enclosing file:line, or nil.
func (a *Analyzer) ForLocation(file string, line int) *normalizer.ReachInfo {
	n, ok := a.Enclosing(file, line)
	if !ok {
		return nil
	}
	info := a.ForNode(n.ID)
	return &info
}

// Downstream is what a function can touch: datastores it (or anything it
// calls) reads or writes, and the dangerous calls along the way.
type Downstream struct {
	Funcs      []int // reachable functions, start included
	Reads      []string
	Writes     []string
	Sinks      []int // sink node IDs
	Sensitive  bool
	Categories []string
}

// Downstream walks call edges from a function and collects what it touches.
func (a *Analyzer) Downstream(id int) Downstream {
	var d Downstream
	reads, writes, cats := map[string]bool{}, map[string]bool{}, map[string]bool{}
	seenSink := map[int]bool{}
	note := func(n graph.Node) {
		if n.PII {
			d.Sensitive = true
		}
		for _, c := range strings.Split(n.Tags[orgcontext.TagSensitiveCategory], ",") {
			if c != "" {
				cats[c] = true
				d.Sensitive = true
			}
		}
	}
	a.walk(id, false, func(f int) {
		d.Funcs = append(d.Funcs, f)
		note(a.G.Nodes[f])
		for _, e := range a.access[f] {
			t := a.G.Nodes[e.Dst]
			switch e.Kind {
			case graph.EdgeReads:
				reads[t.Name] = true
				note(t)
			case graph.EdgeWrites:
				writes[t.Name] = true
				note(t)
			case graph.EdgeContains:
				if !seenSink[e.Dst] {
					seenSink[e.Dst] = true
					d.Sinks = append(d.Sinks, e.Dst)
				}
			}
		}
	})
	d.Reads, d.Writes, d.Categories = sortedKeys(reads), sortedKeys(writes), sortedKeys(cats)
	return d
}

func sortedKeys(m map[string]bool) []string {
	if len(m) == 0 {
		return nil
	}
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Accesses returns a function's own contains/reads/writes edges.
func (a *Analyzer) Accesses(id int) []graph.Edge { return a.access[id] }

// Callers returns the functions that call id directly.
func (a *Analyzer) Callers(id int) []int { return a.callers[id] }

// Reachable reports whether any public entrypoint reaches the function.
func (a *Analyzer) Reachable(id int) bool { return len(a.entries[id]) > 0 }

// Exposed reports whether an unguarded entrypoint reaches the function
// without passing an auth check.
func (a *Analyzer) Exposed(id int) bool { return len(a.unguard[id]) > 0 }

// ClientSide reports whether the function runs in, or is called from,
// browser code.
func (a *Analyzer) ClientSide(id int) bool {
	return a.G.Nodes[id].ClientSide || a.client[id]
}

// EntrypointsReaching returns up to max entrypoints reaching the function,
// unguarded ones first.
func (a *Analyzer) EntrypointsReaching(id, max int) []graph.Node {
	var out []graph.Node
	seen := map[int]bool{}
	for _, list := range [][]int{a.unguard[id], a.entries[id]} {
		for _, e := range list {
			if !seen[e] && len(out) < max {
				seen[e] = true
				out = append(out, a.G.Nodes[e])
			}
		}
	}
	return out
}

// ForNode computes reach data for one function node.
func (a *Analyzer) ForNode(id int) normalizer.ReachInfo {
	n := a.G.Nodes[id]
	d := a.Downstream(id)
	info := normalizer.ReachInfo{
		NodeKey:    n.Key,
		Function:   n.Name,
		Reachable:  a.Reachable(id),
		Reads:      d.Reads,
		Writes:     d.Writes,
		Sensitive:  d.Sensitive,
		Categories: d.Categories,
		ClientSide: a.ClientSide(id),
	}
	info.Guarded = info.Reachable && !a.Exposed(id)
	for _, e := range a.EntrypointsReaching(id, 3) {
		info.Entrypoints = append(info.Entrypoints, fmt.Sprintf("%s (%s)", a.Label(e), a.Loc(e)))
	}
	if (info.Reachable && !info.Guarded) || info.ClientSide {
		info.Priority += 4
	}
	if info.Sensitive {
		info.Priority += 2
	}
	if len(info.Reads)+len(info.Writes) > 0 {
		info.Priority++
	}
	return info
}

// sourceLines returns a file's lines (cached), for reading route decorators.
func (a *Analyzer) sourceLines(file string) []string {
	if lines, ok := a.srcLines[file]; ok {
		return lines
	}
	path := file
	if !filepath.IsAbs(path) {
		path = filepath.Join(a.Root, path)
	}
	data, err := os.ReadFile(path)
	var lines []string
	if err == nil {
		lines = strings.Split(string(data), "\n")
	}
	a.srcLines[file] = lines
	return lines
}
