package graphstore

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/dev-zeph/trojan/internal/graph"
	"github.com/dev-zeph/trojan/internal/rag"
)

// RefreshStats reports how much work a Refresh did, so callers (and tests) can
// confirm an unchanged project costs almost nothing to bring up to date.
type RefreshStats struct {
	FilesTotal    int // source files in a language the graph parses
	FilesReparsed int // of those, how many were actually parsed this time
	Duration      time.Duration
}

// fileHash is one row of the file_hashes table: a source file's content hash
// at the time the persisted graph was built, and the batch it belongs to.
type fileHash struct {
	RelPath  string
	Language string // graph.BatchOf the file
	SHA256   string
}

// metaRootKey is the meta row recording which project root the cached keys
// and file paths were computed against.
const metaRootKey = "root"

// metaBuilderKey records graph.BuilderVersion for the cached graph; a
// different (or missing) value forces a full rebuild.
const metaBuilderKey = "builder"

// Refresh brings the project's persisted graph up to date and returns it.
//
// It hashes every source file and compares against the hashes stored with the
// last graph. Caching is per language batch (graph.BatchGo/BatchJS/
// BatchPython) rather than per file, because the builders resolve calls
// across files within a batch: one changed file can change edges in its
// neighbours. So:
//   - nothing changed: load the graph from graph.db, parse 0 files;
//   - files of batch L added, removed or modified: rebuild only L's files,
//     keep the cached nodes and edges of every other batch, merge, re-run key
//     assignment, save;
//   - no usable cache (first run, a graph written by plain Save, a v1
//     database, or the project moved): full rebuild.
func Refresh(projectRoot string) (*graph.Graph, RefreshStats, error) {
	start := time.Now()
	root, err := filepath.Abs(projectRoot)
	if err != nil {
		return nil, RefreshStats{}, fmt.Errorf("graphstore: resolve %s: %w", projectRoot, err)
	}
	files, err := rag.WalkSource(root)
	if err != nil {
		return nil, RefreshStats{}, fmt.Errorf("graphstore: walk %s: %w", projectRoot, err)
	}

	var cur []fileHash
	byBatch := make(map[string][]string)
	for _, f := range files {
		batch := graph.BatchOf(f)
		if batch == "" {
			continue
		}
		src, err := os.ReadFile(f)
		if err != nil {
			continue // the builders skip unreadable files too
		}
		sum := sha256.Sum256(src)
		rel, err := filepath.Rel(root, f)
		if err != nil {
			rel = f
		}
		cur = append(cur, fileHash{RelPath: filepath.ToSlash(rel), Language: batch, SHA256: hex.EncodeToString(sum[:])})
		byBatch[batch] = append(byBatch[batch], f)
	}
	stats := RefreshStats{FilesTotal: len(cur)}
	// The JS builder also reads tsconfig/jsconfig (path aliases) and uses
	// package.json locations to find the Next.js root, so editing one of those
	// must invalidate the JS batch even though no source file changed.
	cur = append(cur, jsConfigHashes(root, byBatch[graph.BatchJS])...)

	dbPath := filepath.Join(root, DefaultDBPath)
	db, err := open(dbPath)
	if err != nil {
		return nil, RefreshStats{}, err
	}
	prev, prevRoot, err := readHashes(db)
	if err != nil {
		db.Close()
		return nil, RefreshStats{}, err
	}

	// The root row is written only alongside a complete hash set, so its
	// absence (or a different root) means there's no cache to trust.
	full := prevRoot != root || readBuilder(db) != graph.BuilderVersion
	changed := make(map[string]bool)
	if !full {
		seen := make(map[string]bool, len(cur))
		for _, h := range cur {
			seen[h.RelPath] = true
			if p, ok := prev[h.RelPath]; !ok || p != h {
				changed[h.Language] = true
			}
		}
		for rel, p := range prev {
			if !seen[rel] {
				changed[p.Language] = true
			}
		}
	}

	if !full && len(changed) == 0 {
		g, err := loadDB(db)
		db.Close()
		if err != nil {
			return nil, RefreshStats{}, err
		}
		stats.Duration = time.Since(start)
		return g, stats, nil
	}

	var cached *graph.Graph
	if !full {
		g, err := loadDB(db)
		if err != nil {
			db.Close()
			return nil, RefreshStats{}, err
		}
		keep := make(map[string]bool)
		for _, b := range graph.AllBatches {
			if !changed[b] {
				keep[b] = true
			}
		}
		cached = graph.FilterBatches(g, keep)
	}
	db.Close()

	var toParse []string
	for _, b := range graph.AllBatches {
		if full || changed[b] {
			toParse = append(toParse, byBatch[b]...)
		}
	}
	fresh, err := graph.BuildFromFilesRoot(root, toParse)
	if err != nil {
		return nil, RefreshStats{}, fmt.Errorf("graphstore: build: %w", err)
	}
	g := graph.Merge(root, cached, fresh)

	if cur == nil {
		cur = []fileHash{} // non-nil: "cache valid, project has no source"
	}
	if err := save(dbPath, g, cur, root); err != nil {
		return nil, RefreshStats{}, err
	}
	stats.FilesReparsed = len(toParse)
	stats.Duration = time.Since(start)
	return g, stats, nil
}

// readHashes returns the stored file hashes keyed by relpath, plus the project
// root they were recorded for.
func readHashes(db *sql.DB) (map[string]fileHash, string, error) {
	var root string
	err := db.QueryRow(`SELECT value FROM meta WHERE key = ?`, metaRootKey).Scan(&root)
	if err != nil && err != sql.ErrNoRows {
		return nil, "", fmt.Errorf("graphstore: read meta: %w", err)
	}
	rows, err := db.Query(`SELECT relpath, language, sha256 FROM file_hashes`)
	if err != nil {
		return nil, "", fmt.Errorf("graphstore: query file hashes: %w", err)
	}
	defer rows.Close()
	out := make(map[string]fileHash)
	for rows.Next() {
		var h fileHash
		if err := rows.Scan(&h.RelPath, &h.Language, &h.SHA256); err != nil {
			return nil, "", fmt.Errorf("graphstore: scan file hash: %w", err)
		}
		out[h.RelPath] = h
	}
	if err := rows.Err(); err != nil {
		return nil, "", fmt.Errorf("graphstore: iterate file hashes: %w", err)
	}
	return out, root, nil
}

// readBuilder returns the graph.BuilderVersion the cached graph was built
// with, or "" when none was recorded.
func readBuilder(db *sql.DB) string {
	var v string
	if err := db.QueryRow(`SELECT value FROM meta WHERE key = ?`, metaBuilderKey).Scan(&v); err != nil {
		return ""
	}
	return v
}

// writeHashes replaces the file_hashes table and the recorded root inside tx.
// A nil hashes clears both, invalidating the Refresh cache.
func writeHashes(tx *sql.Tx, hashes []fileHash, root string) error {
	if _, err := tx.Exec(`DELETE FROM file_hashes`); err != nil {
		return fmt.Errorf("graphstore: clear file hashes: %w", err)
	}
	if _, err := tx.Exec(`DELETE FROM meta WHERE key IN (?, ?)`, metaRootKey, metaBuilderKey); err != nil {
		return fmt.Errorf("graphstore: clear meta: %w", err)
	}
	if hashes == nil {
		return nil
	}
	if _, err := tx.Exec(`INSERT INTO meta (key, value) VALUES (?, ?), (?, ?)`, metaRootKey, root, metaBuilderKey, graph.BuilderVersion); err != nil {
		return fmt.Errorf("graphstore: write meta: %w", err)
	}
	stmt, err := tx.Prepare(`INSERT INTO file_hashes (relpath, language, sha256) VALUES (?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("graphstore: prepare file hash insert: %w", err)
	}
	defer stmt.Close()
	for _, h := range hashes {
		if _, err := stmt.Exec(h.RelPath, h.Language, h.SHA256); err != nil {
			return fmt.Errorf("graphstore: insert file hash %s: %w", h.RelPath, err)
		}
	}
	return nil
}

// jsConfigFiles are the non-source files the JS builder reads.
var jsConfigFiles = []string{"tsconfig.json", "jsconfig.json", "package.json"}

// jsConfigHashes hashes every jsConfigFiles entry in the directories holding
// JS/TS files and their ancestors up to root, tagged with the JS batch.
func jsConfigHashes(root string, jsFiles []string) []fileHash {
	dirs := make(map[string]bool)
	for _, f := range jsFiles {
		for d := filepath.Dir(f); !dirs[d]; d = filepath.Dir(d) {
			dirs[d] = true
			if d == root || d == filepath.Dir(d) {
				break
			}
		}
	}
	var out []fileHash
	for d := range dirs {
		for _, name := range jsConfigFiles {
			p := filepath.Join(d, name)
			src, err := os.ReadFile(p)
			if err != nil {
				continue
			}
			sum := sha256.Sum256(src)
			rel, err := filepath.Rel(root, p)
			if err != nil {
				rel = p
			}
			out = append(out, fileHash{RelPath: filepath.ToSlash(rel), Language: graph.BatchJS, SHA256: hex.EncodeToString(sum[:])})
		}
	}
	return out
}
