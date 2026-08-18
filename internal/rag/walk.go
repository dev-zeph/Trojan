package rag

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/dev-zeph/trojan/internal/normalizer"
)

// sourceExts are the file extensions worth indexing for code retrieval. Config,
// data, and binary files add noise and cost without helping triage reason about
// code, so they're skipped.
var sourceExts = map[string]bool{
	".go": true, ".ts": true, ".tsx": true, ".js": true, ".jsx": true,
	".mjs": true, ".cjs": true, ".py": true, ".rb": true, ".java": true,
	".php": true, ".rs": true, ".cs": true, ".c": true, ".cc": true,
	".cpp": true, ".cxx": true, ".h": true, ".hpp": true, ".kt": true,
	".swift": true, ".scala": true, ".m": true,
}

// maxIndexFileBytes skips very large files (minified bundles, generated blobs,
// vendored megafiles) that slip past the name/dir filters — they blow the token
// budget and rarely contain the code triage needs.
const maxIndexFileBytes = 512 * 1024

// WalkSource returns absolute paths of source files under root worth indexing,
// skipping non-shipping directories/files (deps, build output, tests, generated —
// the same exclusions as the finding path filter) and oversized files.
func WalkSource(root string) ([]string, error) {
	var files []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // unreadable entry — skip, don't abort the whole walk
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			rel = path
		}
		rel = filepath.ToSlash(rel)

		if d.IsDir() {
			if rel == "." {
				return nil
			}
			// Prune non-shipping and dot directories wholesale (don't descend).
			if normalizer.IsNonShipping(rel) || strings.HasPrefix(d.Name(), ".") {
				return fs.SkipDir // node_modules, vendor, dist, .git, .trojan, .venv, …
			}
			return nil
		}

		if !sourceExts[strings.ToLower(filepath.Ext(path))] {
			return nil
		}
		if normalizer.IsNonShipping(rel) {
			return nil
		}
		if info, statErr := d.Info(); statErr == nil && info.Size() > maxIndexFileBytes {
			return nil
		}
		files = append(files, path)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return files, nil
}

// ProjectHasIndex reports whether an index already exists for a project.
func ProjectHasIndex(projectPath string) bool {
	_, err := os.Stat(IndexPath(projectPath))
	return err == nil
}
