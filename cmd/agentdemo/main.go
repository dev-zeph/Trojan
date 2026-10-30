// Command agentdemo builds Trojan's local Code Property Graph for a path and
// prints the deterministic graph summary (entrypoints, PII, attack paths),
// which is fully offline and needs no key or token.
//
// The live white-box reasoning loop is now hosted (the model key and the
// system prompt live in the whitebox-agent edge function, not in this binary):
// to run it, use `trojan hypothesize <path>`.
//
// Usage:
//
//	go run ./cmd/agentdemo [path]        # path defaults to "."
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/dev-zeph/trojan/internal/agent"
	"github.com/dev-zeph/trojan/internal/graph"
	"github.com/dev-zeph/trojan/internal/rag"
)

func main() {
	root := "."
	if len(os.Args) > 1 {
		root = os.Args[1]
	}

	files, err := goFiles(root)
	if err != nil {
		fmt.Fprintln(os.Stderr, "walk source:", err)
		os.Exit(1)
	}
	if len(files) == 0 {
		fmt.Fprintf(os.Stderr, "no Go source files found under %s\n", root)
		os.Exit(1)
	}

	g, err := graph.BuildFromGoFiles(files)
	if err != nil {
		fmt.Fprintln(os.Stderr, "build graph:", err)
		os.Exit(1)
	}

	tb := agent.NewToolbox(g)
	printSummary(root, len(files), g, tb)

	fmt.Println()
	fmt.Println("The graph and tool layer above ran fully offline. To have Trojan's")
	fmt.Println("hosted white-box reviewer form attack hypotheses over this graph,")
	fmt.Println("run `trojan hypothesize " + root + "` (uses Trojan Tokens).")
}

// goFiles returns the Go source files under root, reusing rag.WalkSource's
// non-shipping filters and keeping only the .go files the graph builder parses.
func goFiles(root string) ([]string, error) {
	all, err := rag.WalkSource(root)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, f := range all {
		if filepath.Ext(f) == ".go" {
			out = append(out, f)
		}
	}
	return out, nil
}

func printSummary(root string, nFiles int, g *graph.Graph, tb *agent.Toolbox) {
	fmt.Printf("== Code Property Graph for %s ==\n", root)
	fmt.Printf("files: %d   nodes: %d   edges: %d\n", nFiles, len(g.Nodes), len(g.Edges))

	eps := tb.ListEntrypoints()
	fmt.Printf("\nentrypoints (sources): %d\n", len(eps))
	for _, e := range eps {
		fmt.Printf("  [%d] %s  (%s)\n", e.ID, e.Name, e.Location)
	}

	pii := tb.GetPIINodes()
	fmt.Printf("\nPII-touching functions: %d\n", len(pii))
	for _, p := range pii {
		fmt.Printf("  [%d] %s  (%s)\n", p.ID, p.Name, p.Location)
	}

	paths := g.Paths()
	fmt.Printf("\nsource -> sink attack paths: %d\n", len(paths))
	for _, p := range paths {
		via := make([]string, 0, len(p.Via))
		for _, n := range p.Via {
			via = append(via, n.Name)
		}
		pii := ""
		if p.TouchPII {
			pii = " [touches PII]"
		}
		fmt.Printf("  (%s) %s -> %s%s\n", p.Severity, strings.Join(via, " -> "), p.Sink.Name, pii)
	}
}
