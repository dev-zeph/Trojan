package graph

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/dev-zeph/trojan/internal/graph/tswasm"
)

// Language batches. A batch is the unit the builders resolve within (cross-
// file resolution happens inside one batch), so it is also the unit
// incremental Refresh caches and rebuilds: if any file of a batch changes, the
// whole batch is rebuilt. JavaScript and TypeScript share one batch because a
// Next.js app freely imports across .js/.ts files.
const (
	BatchGo     = "go"
	BatchJS     = "js"
	BatchPython = "py"
)

// AllBatches lists every batch in build order.
var AllBatches = []string{BatchGo, BatchJS, BatchPython}

// BatchOf returns the batch a source file belongs to, or "" for a language
// the graph doesn't parse.
func BatchOf(path string) string {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".go":
		return BatchGo
	case ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx":
		return BatchJS
	case ".py":
		return BatchPython
	}
	return ""
}

// BuildFromFiles builds a single Code Property Graph from a mixed-language
// file set. It routes .go files through the go/ast path and
// .js/.jsx/.mjs/.cjs/.ts/.tsx/.py files through the tree-sitter-WASM path
// (tswasm, run via wazero, no CGO). Files in unrecognized languages are
// ignored, same policy as an unparseable file.
//
// Node keys are made relative to a root inferred from the files (the nearest
// ancestor of their common directory holding a project marker such as .git
// or go.mod). Callers that know the project root should prefer
// BuildFromFilesRoot so keys don't depend on that guess.
func BuildFromFiles(files []string) (*Graph, error) {
	return BuildFromFilesRoot(inferRoot(files), files)
}

// BuildFromFilesRoot is BuildFromFiles with an explicit project root, against
// which node keys (contract C1) are computed.
//
// The tree-sitter WASM runtime is created once and shared across every
// non-Go file; the compiled module itself is cached process-wide by tswasm,
// so repeated builds don't pay the compile cost again.
func BuildFromFilesRoot(root string, files []string) (*Graph, error) {
	var goFiles, jsFiles, tsFiles, pyFiles []string
	for _, f := range files {
		switch BatchOf(f) {
		case BatchGo:
			goFiles = append(goFiles, f)
		case BatchJS:
			switch strings.ToLower(filepath.Ext(f)) {
			case ".ts", ".tsx":
				tsFiles = append(tsFiles, f)
			default:
				jsFiles = append(jsFiles, f)
			}
		case BatchPython:
			pyFiles = append(pyFiles, f)
		}
	}

	combined := New()

	if len(goFiles) > 0 {
		g := buildGo(goFiles)
		tagBatch(g, BatchGo)
		mergeInto(combined, g)
	}

	if len(jsFiles) > 0 || len(tsFiles) > 0 || len(pyFiles) > 0 {
		ctx := context.Background()
		rt, err := tswasm.NewRuntime(ctx)
		if err != nil {
			// The WASM path is best-effort language coverage on top of the
			// Go path; a runtime failure (e.g. no WASM support in this
			// environment) shouldn't take down a build that has real Go
			// files. Report it only if there's nothing else to build.
			if len(goFiles) == 0 {
				return nil, err
			}
			AssignKeys(combined, root)
			return combined, nil
		}
		defer rt.Close(ctx)

		if len(jsFiles) > 0 {
			lang, err := rt.JavaScript(ctx)
			if err == nil {
				if g, err := buildFromJSFiles(ctx, rt, lang, jsFiles); err == nil {
					tagBatch(g, BatchJS)
					mergeInto(combined, g)
				}
			}
		}
		if len(tsFiles) > 0 {
			lang, err := rt.TypeScript(ctx)
			if err == nil {
				if g, err := buildFromJSFiles(ctx, rt, lang, tsFiles); err == nil {
					tagBatch(g, BatchJS)
					mergeInto(combined, g)
				}
			}
		}
		if len(pyFiles) > 0 {
			lang, err := rt.Python(ctx)
			if err == nil {
				if g, err := buildFromPythonFiles(ctx, rt, lang, pyFiles); err == nil {
					tagBatch(g, BatchPython)
					mergeInto(combined, g)
				}
			}
		}
	}

	AssignKeys(combined, root)
	return combined, nil
}

// Merge combines graphs (e.g. the cached batches of a previous build plus a
// freshly rebuilt batch) into one, then re-runs key assignment, which also
// folds datastore nodes that share a key into one. Inputs are not modified.
func Merge(root string, parts ...*Graph) *Graph {
	combined := New()
	for _, p := range parts {
		if p == nil {
			continue
		}
		cp := &Graph{Nodes: make([]Node, len(p.Nodes)), Edges: p.Edges}
		for i, n := range p.Nodes {
			n.Tags = copyTags(n.Tags)
			n.Batches = append([]string(nil), n.Batches...)
			cp.Nodes[i] = n
		}
		mergeInto(combined, cp)
	}
	AssignKeys(combined, root)
	return combined
}

// FilterBatches returns the part of g produced by the given batches: nodes
// whose Batches intersect keep (with Batches narrowed to that intersection)
// and the edges those batches own. Every edge starts at a func, which belongs
// to exactly one batch, so an edge is owned by its source node's batch. Nodes
// with no batch recorded are dropped, since nothing can say whether they're
// still current. g is not modified.
func FilterBatches(g *Graph, keep map[string]bool) *Graph {
	out := New()
	remap := make(map[int]int, len(g.Nodes))
	owner := make(map[int]bool, len(g.Nodes)) // all of the node's batches kept
	for _, n := range g.Nodes {
		var bs []string
		for _, b := range n.Batches {
			if keep[b] {
				bs = append(bs, b)
			}
		}
		if len(bs) == 0 {
			continue
		}
		owner[n.ID] = len(bs) == len(n.Batches)
		n.Batches = bs
		n.Tags = copyTags(n.Tags)
		remap[n.ID] = out.addNode(n)
	}
	for _, e := range g.Edges {
		src, okS := remap[e.Src]
		dst, okD := remap[e.Dst]
		if okS && okD && owner[e.Src] {
			out.addEdge(src, dst, e.Kind)
		}
	}
	return out
}

// mergeInto appends every node and edge from src into dst, remapping IDs so
// they don't collide with whatever dst already holds. Each language builder
// returns a self-contained *Graph (independently useful/testable); the
// dispatch layer's only extra job is combining them into one graph so callers
// get "the CPG for this repo" regardless of what languages it's written in.
func mergeInto(dst, src *Graph) {
	offset := len(dst.Nodes)
	dst.Nodes = append(dst.Nodes, src.Nodes...)
	for _, e := range src.Edges {
		dst.Edges = append(dst.Edges, Edge{Src: e.Src + offset, Dst: e.Dst + offset, Kind: e.Kind})
	}
	// Node.ID fields were assigned relative to src; fix them up to match
	// their new position in dst so Node.ID stays consistent with its index.
	for i := offset; i < len(dst.Nodes); i++ {
		dst.Nodes[i].ID = i
	}
}

// tagBatch records batch as the producer of every node in g.
func tagBatch(g *Graph, batch string) {
	for i := range g.Nodes {
		g.Nodes[i].Batches = []string{batch}
	}
}

func copyTags(t map[string]string) map[string]string {
	if t == nil {
		return nil
	}
	out := make(map[string]string, len(t))
	for k, v := range t {
		out[k] = v
	}
	return out
}

// rootMarkers are files/dirs whose presence marks a project root.
var rootMarkers = []string{".git", ".trojan", "go.mod", "package.json", "pyproject.toml", "requirements.txt"}

// inferRoot guesses the project root for a file list: the nearest ancestor of
// the files' common directory that holds a root marker, else the common
// directory itself.
func inferRoot(files []string) string {
	common := ""
	for _, f := range files {
		abs, err := filepath.Abs(f)
		if err != nil {
			continue
		}
		dir := filepath.Dir(abs)
		if common == "" {
			common = dir
			continue
		}
		for !within(dir, common) {
			parent := filepath.Dir(common)
			if parent == common {
				break
			}
			common = parent
		}
	}
	if common == "" {
		return "."
	}
	for dir := common; ; {
		for _, m := range rootMarkers {
			if _, err := os.Stat(filepath.Join(dir, m)); err == nil {
				return dir
			}
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return common
		}
		dir = parent
	}
}

// within reports whether path is dir or lies beneath it.
func within(path, dir string) bool {
	rel, err := filepath.Rel(dir, path)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// sortedBatches returns a batch set as a list in AllBatches order (unknown
// names last, alphabetically), so batch lists are deterministic.
func sortedBatches(set map[string]bool) []string {
	rank := func(b string) int {
		for i, x := range AllBatches {
			if x == b {
				return i
			}
		}
		return len(AllBatches)
	}
	out := make([]string, 0, len(set))
	for b := range set {
		out = append(out, b)
	}
	sort.Slice(out, func(i, j int) bool {
		ri, rj := rank(out[i]), rank(out[j])
		if ri != rj {
			return ri < rj
		}
		return out[i] < out[j]
	})
	return out
}
