// Command agentdemo builds Trojan's local Code Property Graph for a path and
// runs the hypothesis-driven agent loop over it.
//
// It always prints the deterministic graph summary (entrypoints, PII, attack
// paths), which needs no API key. It then runs the live Claude reasoning loop
// ONLY when ANTHROPIC_API_KEY is set; without a key it prints a clear message
// and exits cleanly, so the demo is safe to build and run offline.
//
// Usage:
//
//	go run ./cmd/agentdemo [path]        # path defaults to "."
//
// Env:
//
//	ANTHROPIC_API_KEY    required to run the live loop; absent => graph only
//	TROJAN_AGENT_MODEL   override the Claude model id (default agent.DefaultModel)
//	TROJAN_ORG_CONTEXT   free-form org context folded into the model's reasoning
package main

import (
	"context"
	"errors"
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

	// Gate: no key means no live call. Clear message, clean exit.
	if strings.TrimSpace(os.Getenv("ANTHROPIC_API_KEY")) == "" {
		fmt.Println()
		fmt.Println("ANTHROPIC_API_KEY is not set, so the live reasoning loop is disabled.")
		fmt.Println("The graph and tool layer above ran fully offline. Set ANTHROPIC_API_KEY to")
		fmt.Println("have Claude form an attack hypothesis over this graph.")
		return
	}

	fmt.Println()
	fmt.Println("== Running hypothesis loop (Claude) ==")
	cfg := agent.Config{
		Model:      os.Getenv("TROJAN_AGENT_MODEL"),
		OrgContext: os.Getenv("TROJAN_ORG_CONTEXT"),
		Logf:       func(format string, args ...any) { fmt.Printf("  "+format+"\n", args...) },
	}

	finding, err := agent.RunHypothesisLoop(context.Background(), tb, cfg)
	if err != nil {
		if errors.Is(err, agent.ErrNoFinding) {
			fmt.Println("The model finished without emitting a finding.")
			return
		}
		fmt.Fprintln(os.Stderr, "hypothesis loop:", err)
		os.Exit(1)
	}

	fmt.Println()
	fmt.Println("== Finding ==")
	fmt.Printf("Hypothesis: %s\n", finding.Hypothesis)
	fmt.Printf("Severity:   %s\n", finding.Severity)
	fmt.Printf("Path:       %s\n", strings.Join(finding.Path, " -> "))
	fmt.Printf("Rationale:  %s\n", finding.Rationale)
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
