package main

import (
	"github.com/fatih/color"

	"github.com/dev-zeph/trojan/internal/graph"
	"github.com/dev-zeph/trojan/internal/graphstore"
	"github.com/dev-zeph/trojan/internal/normalizer"
	"github.com/dev-zeph/trojan/internal/reach"
)

// enrichWithGraph is the scan path's hook into the security brain: it
// refreshes .trojan/graph.db, re-applies .trojan/context.yaml and attaches
// reach data (public route? login check? which tables?) to each finding,
// ranking exposed ones first. A graph failure never fails the scan.
func enrichWithGraph(path string, findings []normalizer.Finding) {
	if err := reach.Enrich(path, findings); err != nil {
		color.Yellow("  Warning: code graph not updated: %s\n", err)
	}
}

// refreshGraph brings the project's persisted graph up to date
// (incrementally) for `trojan context scan`. The caller applies the org
// context overlay, since Refresh doesn't keep it.
func refreshGraph(path string) (*graph.Graph, error) {
	g, _, err := graphstore.Refresh(path)
	return g, err
}
