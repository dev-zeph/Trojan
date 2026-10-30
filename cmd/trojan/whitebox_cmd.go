package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	ctxagent "github.com/dev-zeph/trojan/internal/agent"
	"github.com/dev-zeph/trojan/internal/config"
	"github.com/dev-zeph/trojan/internal/graphstore"
	"github.com/dev-zeph/trojan/internal/memory"
	"github.com/dev-zeph/trojan/internal/orgcontext"
)

// `trojan hypothesize` runs the hosted white-box reviewer over a project's
// code graph and saves concrete, testable attack hypotheses to
// .trojan/hypotheses.json. It is the local orchestrator for the loop in
// internal/agent: it builds the graph, applies the org-context overlay, wires
// the local tools (graph + grey-box source + memory), and drives the loop
// through the whitebox-agent edge function. The reasoning is billed in Trojan
// Tokens; the graph and every tool run locally.

func whiteboxCmd() *cobra.Command {
	var maxTurns, maxTokens, maxHypotheses int
	cmd := &cobra.Command{
		Use:   "hypothesize [path]",
		Short: "Form concrete, testable attack hypotheses from your code (uses Trojan Tokens)",
		Long: `Builds Trojan's local Code Property Graph for the project, layers on your
org context and past results, and has Trojan's hosted white-box reviewer form
a short list of high-precision, testable attack hypotheses, which it saves to
.trojan/hypotheses.json. The agentic pen test reads that file to focus its
probes, so run this first.

The graph and every tool run locally; only the reasoning is hosted, and it is
billed in Trojan Tokens.`,
		Args: cobra.MaximumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			path := "."
			if len(args) > 0 {
				path = args[0]
			}

			cfg, _ := config.LoadConfig()
			accessToken := ""
			if cfg != nil {
				accessToken = cfg.AccessToken
			}
			if accessToken == "" {
				color.Yellow("Not logged in. Run `trojan login` first. The white-box reviewer is billed to your account.\n")
				os.Exit(1)
			}

			opts := ctxagent.Options{
				MaxTurns:      maxTurns,
				MaxTokens:     maxTokens,
				MaxHypotheses: maxHypotheses,
				Logf:          func(format string, a ...any) { fmt.Printf("  "+format+"\n", a...) },
			}
			res, err := runWhitebox(context.Background(), path, accessToken, opts)
			if err != nil {
				if errors.Is(err, ctxagent.ErrInsufficientTokens) {
					color.Red("\nYou are out of Trojan Tokens. Top up to run the white-box reviewer.\n")
					os.Exit(1)
				}
				color.Red("Error: %s\n", err)
				os.Exit(1)
			}
			if res == nil {
				fmt.Println("No code graph could be built for this project, so there is nothing to reason over.")
				return
			}

			fmt.Println()
			if len(res.Hypotheses) == 0 {
				fmt.Println("No hypotheses: the reviewer did not find a testable weakness worth proving.")
			} else {
				fmt.Printf("%d hypothesis/hypotheses saved to %s:\n\n", len(res.Hypotheses), filepath.Join(path, ctxagent.HypothesesPath))
				for _, h := range res.Hypotheses {
					fmt.Printf("  [%s] %s (%s)\n", h.Confidence, h.Title, h.Class)
					fmt.Printf("      test   : %s\n", h.Endpoint())
					if h.Impact != "" {
						fmt.Printf("      impact : %s\n", h.Impact)
					}
				}
			}
			if res.Summary != "" {
				fmt.Printf("\n%s\n", res.Summary)
			}
			fmt.Printf("\nStopped: %s. %d turn(s), ~%d LLM tokens.\n", res.StopReason, res.Turns, res.Usage.Total())
		},
	}
	cmd.Flags().IntVar(&maxTurns, "max-turns", 0, "Cap reasoning turns (default 12)")
	cmd.Flags().IntVar(&maxTokens, "max-tokens", 0, "Cumulative LLM-token ceiling (default 0 = no ceiling; usage is token-metered)")
	cmd.Flags().IntVar(&maxHypotheses, "max-hypotheses", 0, "Cap how many hypotheses to keep (default 8)")
	return cmd
}

// runWhitebox builds the graph for root, wires the local toolbox and drives
// the hosted loop. It returns (nil, nil) when no graph could be built, saves
// the hypotheses to .trojan/hypotheses.json, and never spends tokens on a build
// error. Shared by the command and the dast-agentic chaining.
func runWhitebox(ctx context.Context, root, accessToken string, opts ctxagent.Options) (*ctxagent.Result, error) {
	absRoot := root
	if abs, err := filepath.Abs(root); err == nil {
		absRoot = abs
	}

	g, _, err := graphstore.Refresh(absRoot)
	if err != nil || g == nil || len(g.Nodes) == 0 {
		return nil, nil //nolint:nilerr // no graph = nothing to reason over, not a failure
	}

	// Org context: load, render for the seed, and overlay onto the graph so the
	// reviewer's tools see the owner's sensitive-data and trust-boundary tags.
	var orgText string
	ctxPath := orgcontext.Path(absRoot)
	if orgcontext.Exists(ctxPath) {
		if oc, lerr := orgcontext.Load(ctxPath); lerr == nil && oc != nil {
			orgcontext.ApplyOverlay(g, oc)
			orgText = orgContextText(oc)
		}
	}

	tb := ctxagent.NewToolbox(g)
	// Grey-box source reader (endpoint/symbol/query), when the project has
	// recognizable routes or a code index.
	if gb := buildGreyBox(absRoot, accessToken); gb != nil {
		tb.WithSource(gb)
	}
	// Memory: only when it already exists, so we never create .trojan/memory.db
	// just by reasoning.
	if _, serr := os.Stat(filepath.Join(absRoot, filepath.FromSlash(memory.DefaultDBPath))); serr == nil {
		if st, oerr := memory.Open(absRoot); oerr == nil {
			defer st.Close()
			tb.WithHistory(st)
		}
	}

	seed := ctxagent.BuildSeed(ctxagent.SeedInput{
		Project:     filepath.Base(absRoot),
		OrgContext:  orgText,
		EndpointMap: greyBoxTable(absRoot, accessToken),
		Nodes:       len(g.Nodes),
		Unguarded:   len(g.UnguardedPaths()),
		Exposures:   len(g.ClientExposures()),
	}, opts)

	tr := ctxagent.NewEdgeTransport(accessToken)
	res, runErr := ctxagent.Run(ctx, tb, tr, seed, opts)

	// Save whatever was emitted before any error, so a run that ran out of
	// tokens mid-way still leaves usable hypotheses behind.
	if res != nil && len(res.Hypotheses) > 0 {
		_ = ctxagent.SaveHypotheses(absRoot, ctxagent.HypothesisFile{
			GeneratedAt: time.Now(),
			RunID:       res.RunID,
			Hypotheses:  res.Hypotheses,
		})
	}
	return res, runErr
}

// runHypothesizeStep is the chained white-box pass the agentic pen test runs
// first: it forms a short list of hypotheses over the source with a small
// bounded budget and saves them to .trojan/hypotheses.json, which the brain
// seed then reads into its "HYPOTHESES TO PROVE" block. It returns the
// hypotheses so the caller can record per-hypothesis outcomes after the run.
//
// It runs only when a project root is known and grey-box is on, and is skipped
// by --no-hypothesize. Any failure (no graph, no tokens, network) is
// swallowed: the pen test must proceed regardless, just without the extra
// focus. Returns nil when skipped or on any failure.
func runHypothesizeStep(root, accessToken string, greyBox, noHypothesize bool) []ctxagent.Hypothesis {
	if root == "" || !greyBox || noHypothesize {
		return nil
	}
	fmt.Printf("  → White-box review: forming hypotheses from the source...\n")
	res, err := runWhitebox(context.Background(), root, accessToken, ctxagent.Options{
		MaxTurns:      6,
		MaxHypotheses: 6,
	})
	if err != nil {
		if errors.Is(err, ctxagent.ErrInsufficientTokens) {
			color.Yellow("  White-box review skipped: out of Trojan Tokens.\n\n")
		} else {
			color.Yellow("  White-box review skipped: %s\n\n", err)
		}
		if res == nil {
			return nil
		}
		return res.Hypotheses
	}
	if res == nil {
		return nil
	}
	fmt.Printf("  → %d hypothesis/hypotheses to prove\n\n", len(res.Hypotheses))
	return res.Hypotheses
}

// greyBoxTable returns the grey-box endpoint->handler lines for the seed, or
// nil when no grey-box reader is available.
func greyBoxTable(root, accessToken string) []string {
	gb := buildGreyBox(root, accessToken)
	if gb == nil {
		return nil
	}
	return gb.EndpointTable()
}
