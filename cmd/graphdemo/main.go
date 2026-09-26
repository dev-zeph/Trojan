// Command graphdemo builds Trojan's Code Property Graph for a Go codebase and
// prints the source->sink attack paths it finds — a runnable demo of the
// context-engine white-box layer (docs/context-engine.md, Phase 0-1).
//
// Usage:
//
//	go run ./cmd/graphdemo <path-to-repo>
//
// It reuses internal/rag's source walker for the file set, so the same
// non-shipping exclusions apply. Everything runs locally and CGO-free; nothing
// leaves the machine.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/dev-zeph/trojan/internal/graph"
	"github.com/dev-zeph/trojan/internal/rag"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: graphdemo <path-to-repo>")
		os.Exit(2)
	}
	root := os.Args[1]

	files, err := rag.WalkSource(root)
	if err != nil {
		fmt.Fprintf(os.Stderr, "walk: %v\n", err)
		os.Exit(1)
	}

	// BuildFromFiles routes each file by extension: Go via go/ast, JS/TS/Python
	// via the tree-sitter WASM pipeline (wazero, CGO-free).
	g, err := graph.BuildFromFiles(files)
	if err != nil {
		fmt.Fprintf(os.Stderr, "build: %v\n", err)
		os.Exit(1)
	}

	var funcs, sinks, sources int
	for _, n := range g.Nodes {
		switch {
		case n.Kind == graph.KindSink:
			sinks++
		case n.Source:
			funcs++
			sources++
		case n.Kind == graph.KindFunc:
			funcs++
		}
	}

	fmt.Printf("Code Property Graph for %s\n", root)
	fmt.Printf("  files scanned    : %d  (Go, JS, TS, Python)\n", len(files))
	fmt.Printf("  functions        : %d\n", funcs)
	fmt.Printf("  entrypoints      : %d  (untrusted sources)\n", sources)
	fmt.Printf("  sinks            : %d  (dangerous calls)\n", sinks)
	fmt.Printf("  edges            : %d\n\n", len(g.Edges))

	paths := g.Paths()
	if len(paths) == 0 {
		fmt.Println("No source->sink attack paths found.")
		return
	}

	fmt.Printf("%d attack path(s) — entrypoint reaching a dangerous sink:\n\n", len(paths))
	for i, p := range paths {
		pii := ""
		if p.TouchPII {
			pii = "  [touches PII/PHI]"
		}
		fmt.Printf("[%d] %s severity%s\n", i+1, strings.ToUpper(p.Severity), pii)
		fmt.Printf("    what : %s\n", p.Sink.SinkRule)
		fmt.Printf("    from : %s (%s:%d)\n", p.Source.Name, short(p.Source.File, root), p.Source.Line)
		fmt.Printf("    path : %s\n", chainString(p.Via))
		fmt.Printf("    sink : %s (%s:%d)\n\n", p.Sink.Name, short(p.Sink.File, root), p.Sink.Line)
	}
}

func chainString(chain []graph.Node) string {
	names := make([]string, len(chain))
	for i, n := range chain {
		names[i] = n.Name
	}
	return strings.Join(names, " -> ")
}

func short(path, root string) string {
	if rel, err := filepath.Rel(root, path); err == nil {
		return rel
	}
	return path
}
