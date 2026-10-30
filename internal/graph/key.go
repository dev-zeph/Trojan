package graph

import (
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Stable node keys (contract C1). A key names a node the same way on every
// build of the same tree, so memory, tools and the agent can refer to "this
// function" or "this sink" across scans. Keys never contain line numbers, so
// unrelated edits (a comment or blank lines above a function) don't move them.
//
//	func:      "<relpath>#<qualified symbol>"       e.g. "app/api/orders/route.ts#POST"
//	sink:      "<func key>@<callee>#<n>"            e.g. "server.js#search@pool.query#1"
//	datastore: "datastore:<name>"                   e.g. "datastore:orders"
//
// relpath is relative to the project root with forward slashes. n counts the
// sinks with that callee inside the function, from 1, in source order. Two
// functions that would get the same key (e.g. two anonymous callbacks in one
// file, or two classes' "get" methods) are told apart by a "#2", "#3", ...
// suffix in source order.

// TopLevel stands in for the enclosing function of code that runs outside
// any function (module-level JS/Python), in sink keys.
const TopLevel = "<toplevel>"

// anonLineSuffix matches the "@<path>:<line>" suffix builders give functions
// they can't name, which must not leak line numbers into keys.
var anonLineSuffix = regexp.MustCompile(`@[^#@]*:\d+$`)

var spaceRun = regexp.MustCompile(`\s+`)

// AssignKeys sets Node.Key on every node of g, relative to root, then folds
// datastore nodes that share a key into one node (unioning their Batches and
// Tags and rewiring edges), since a datastore is identified by name alone.
// It recomputes every key from Name/File, so it is safe to run repeatedly,
// and it is run after every build and every Merge.
func AssignKeys(g *Graph, root string) {
	absRoot, err := filepath.Abs(root)
	if err != nil {
		absRoot = root
	}

	// Funcs: base key, then disambiguate collisions in source order.
	byBase := make(map[string][]int)
	for i := range g.Nodes {
		n := &g.Nodes[i]
		if n.Kind != KindFunc {
			continue
		}
		base := relPath(absRoot, n.File) + "#" + funcSymbol(n)
		byBase[base] = append(byBase[base], i)
	}
	for base, ids := range byBase {
		sortBySource(g, ids)
		for k, id := range ids {
			if k == 0 {
				g.Nodes[id].Key = base
			} else {
				g.Nodes[id].Key = base + "#" + strconv.Itoa(k+1)
			}
		}
	}

	// Sinks: owned by the function that contains them.
	container := make(map[int]int)
	for _, e := range g.Edges {
		if e.Kind == EdgeContains && g.Nodes[e.Src].Kind == KindFunc {
			if _, seen := container[e.Dst]; !seen {
				container[e.Dst] = e.Src
			}
		}
	}
	bySite := make(map[string][]int)
	for i := range g.Nodes {
		n := &g.Nodes[i]
		if n.Kind != KindSink {
			continue
		}
		owner := relPath(absRoot, n.File) + "#" + TopLevel
		if fn, ok := container[i]; ok {
			owner = g.Nodes[fn].Key
		}
		site := owner + "@" + sinkCallee(n.Name)
		bySite[site] = append(bySite[site], i)
	}
	for site, ids := range bySite {
		sortBySource(g, ids)
		for k, id := range ids {
			g.Nodes[id].Key = site + "#" + strconv.Itoa(k+1)
		}
	}

	// Datastores, and a generic fallback for any future kind.
	for i := range g.Nodes {
		n := &g.Nodes[i]
		switch n.Kind {
		case KindFunc, KindSink:
		case KindDataStore:
			n.Key = "datastore:" + strings.TrimSpace(n.Name)
		default:
			n.Key = relPath(absRoot, n.File) + "#" + string(n.Kind) + ":" + strings.TrimSpace(n.Name)
		}
	}

	foldDatastores(g)
}

// funcSymbol is the qualified symbol part of a func key: the node's Name,
// minus the "<file basename>." namespace the tree-sitter builders prepend
// (the relpath already says which file) and minus any "@<path>:<line>"
// anonymous-function suffix.
func funcSymbol(n *Node) string {
	name := n.Name
	if n.File != "" {
		if i := strings.Index(name, "@"+n.File+":"); i >= 0 {
			name = name[:i]
		}
		name = strings.TrimPrefix(name, filepath.Base(n.File)+".")
	}
	name = anonLineSuffix.ReplaceAllString(name, "")
	if name == "" {
		name = "anonymous"
	}
	return name
}

// sinkCallee normalizes a sink's Name to the callee text: whitespace collapsed
// and any argument list dropped, so "db.query(\n  sql)" keys as "db.query".
func sinkCallee(name string) string {
	if i := strings.Index(name, "("); i > 0 {
		name = name[:i]
	}
	name = spaceRun.ReplaceAllString(strings.TrimSpace(name), "")
	if name == "" {
		name = "call"
	}
	return name
}

// relPath returns file relative to root with forward slashes. Files outside
// root (or when either path can't be made absolute) keep their full path.
func relPath(absRoot, file string) string {
	if file == "" {
		return ""
	}
	abs, err := filepath.Abs(file)
	if err != nil {
		return filepath.ToSlash(file)
	}
	rel, err := filepath.Rel(absRoot, abs)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return filepath.ToSlash(abs)
	}
	return filepath.ToSlash(rel)
}

// sortBySource orders node indexes by line, then by build order, which is
// source order within one file.
func sortBySource(g *Graph, ids []int) {
	sort.SliceStable(ids, func(a, b int) bool {
		na, nb := g.Nodes[ids[a]], g.Nodes[ids[b]]
		if na.Line != nb.Line {
			return na.Line < nb.Line
		}
		return ids[a] < ids[b]
	})
}

// foldDatastores merges datastore nodes with the same Key into the first one
// in (File, Line) order, unions Batches and Tags, rewires edges to the
// survivor, and renumbers node IDs. Duplicate edges into a datastore are
// dropped.
func foldDatastores(g *Graph) {
	groups := make(map[string][]int)
	for i, n := range g.Nodes {
		if n.Kind == KindDataStore {
			groups[n.Key] = append(groups[n.Key], i)
		}
	}
	redirect := make(map[int]int)
	for _, ids := range groups {
		if len(ids) < 2 {
			continue
		}
		sort.SliceStable(ids, func(a, b int) bool {
			na, nb := g.Nodes[ids[a]], g.Nodes[ids[b]]
			if na.File != nb.File {
				return na.File < nb.File
			}
			return na.Line < nb.Line
		})
		keep := ids[0]
		batches := make(map[string]bool)
		for _, id := range ids {
			for _, b := range g.Nodes[id].Batches {
				batches[b] = true
			}
			if id == keep {
				continue
			}
			for k, v := range g.Nodes[id].Tags {
				if g.Nodes[keep].Tags == nil {
					g.Nodes[keep].Tags = make(map[string]string)
				}
				if _, set := g.Nodes[keep].Tags[k]; !set {
					g.Nodes[keep].Tags[k] = v
				}
			}
			redirect[id] = keep
		}
		g.Nodes[keep].Batches = sortedBatches(batches)
	}
	newID := make(map[int]int, len(g.Nodes))
	nodes := make([]Node, 0, len(g.Nodes)-len(redirect))
	for i, n := range g.Nodes {
		if _, gone := redirect[i]; gone {
			continue
		}
		n.ID = len(nodes)
		newID[i] = n.ID
		nodes = append(nodes, n)
	}
	resolve := func(id int) int {
		if to, ok := redirect[id]; ok {
			id = to
		}
		return newID[id]
	}
	// Edges into a datastore are a set ("f writes orders"), whether or not a
	// fold happened, so the result doesn't depend on how many datastore nodes
	// a builder emitted or which batches were merged together.
	seen := make(map[Edge]bool)
	edges := make([]Edge, 0, len(g.Edges))
	for _, e := range g.Edges {
		ne := Edge{Src: resolve(e.Src), Dst: resolve(e.Dst), Kind: e.Kind}
		if nodes[ne.Dst].Kind == KindDataStore {
			if seen[ne] {
				continue
			}
			seen[ne] = true
		}
		edges = append(edges, ne)
	}
	g.Nodes, g.Edges = nodes, edges
}
