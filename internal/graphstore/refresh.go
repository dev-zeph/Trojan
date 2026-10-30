package graphstore

import (
	"fmt"
	"path/filepath"
	"time"

	"github.com/dev-zeph/trojan/internal/graph"
	"github.com/dev-zeph/trojan/internal/rag"
)

// RefreshStats reports how much work a Refresh did, so callers (and tests) can
// confirm an unchanged project costs almost nothing to bring up to date.
type RefreshStats struct {
	FilesTotal    int
	FilesReparsed int
	Duration      time.Duration
}

// Refresh brings the project's persisted graph up to date and returns it:
// load the cache, re-parse only files whose content changed, re-merge and
// re-resolve, save.
//
// CONTRACT (Wave 0): this first version always does a full rebuild. The
// incremental version replaces the body without changing the signature.
func Refresh(projectRoot string) (*graph.Graph, RefreshStats, error) {
	start := time.Now()
	files, err := rag.WalkSource(projectRoot)
	if err != nil {
		return nil, RefreshStats{}, fmt.Errorf("graphstore: walk %s: %w", projectRoot, err)
	}
	g, err := graph.BuildFromFiles(files)
	if err != nil {
		return nil, RefreshStats{}, fmt.Errorf("graphstore: build: %w", err)
	}
	if err := Save(filepath.Join(projectRoot, DefaultDBPath), g); err != nil {
		return nil, RefreshStats{}, err
	}
	return g, RefreshStats{FilesTotal: len(files), FilesReparsed: len(files), Duration: time.Since(start)}, nil
}
