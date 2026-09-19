package graph

import (
	"context"
	"path/filepath"
	"strings"

	"github.com/dev-zeph/trojan/internal/graph/tswasm"
)

// BuildFromFiles builds a single Code Property Graph from a mixed-language
// file set. It routes .go files through the go/ast path (BuildFromGoFiles,
// unchanged) and .js/.jsx/.mjs/.cjs/.ts/.tsx/.py files through the
// tree-sitter-WASM path (tswasm, run via wazero, no CGO). Files in
// unrecognized languages are ignored, same policy as an unparseable file.
//
// The tree-sitter WASM runtime is created once and shared across every
// non-Go file, since compiling the ~6MB embedded module is the expensive
// part; it's closed before returning.
func BuildFromFiles(files []string) (*Graph, error) {
	var goFiles, jsFiles, tsFiles, pyFiles []string
	for _, f := range files {
		switch strings.ToLower(filepath.Ext(f)) {
		case ".go":
			goFiles = append(goFiles, f)
		case ".js", ".jsx", ".mjs", ".cjs":
			jsFiles = append(jsFiles, f)
		case ".ts", ".tsx":
			tsFiles = append(tsFiles, f)
		case ".py":
			pyFiles = append(pyFiles, f)
		}
	}

	combined := New()

	if len(goFiles) > 0 {
		g, err := BuildFromGoFiles(goFiles)
		if err != nil {
			return nil, err
		}
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
			return combined, nil
		}
		defer rt.Close(ctx)

		if len(jsFiles) > 0 {
			lang, err := rt.JavaScript(ctx)
			if err == nil {
				if g, err := buildFromJSFiles(ctx, rt, lang, jsFiles); err == nil {
					mergeInto(combined, g)
				}
			}
		}
		if len(tsFiles) > 0 {
			lang, err := rt.TypeScript(ctx)
			if err == nil {
				if g, err := buildFromJSFiles(ctx, rt, lang, tsFiles); err == nil {
					mergeInto(combined, g)
				}
			}
		}
		if len(pyFiles) > 0 {
			lang, err := rt.Python(ctx)
			if err == nil {
				if g, err := buildFromPythonFiles(ctx, rt, lang, pyFiles); err == nil {
					mergeInto(combined, g)
				}
			}
		}
	}

	return combined, nil
}

// mergeInto appends every node and edge from src into dst, remapping IDs so
// they don't collide with whatever dst already holds. Each language builder
// returns a self-contained *Graph (same shape BuildFromGoFiles returns, and
// independently useful/testable); BuildFromFiles's only extra job is combining
// them into one graph so Paths() can find routes that cross... well, routes
// don't cross languages here (call resolution is per-file/per-language), but
// a single combined Graph is still the natural shape for callers that want
// "the CPG for this repo" regardless of what languages it's written in.
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
