package rag

import (
	"crypto/sha256"
	"encoding/gob"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
)

// Entry is one chunk paired with its embedding vector.
type Entry struct {
	Chunk  Chunk
	Vector []float32
}

// Result is a chunk retrieved by similarity search, with its cosine score.
type Result struct {
	Chunk Chunk
	Score float64 // cosine similarity in [-1, 1]
}

// Store is a per-repository, on-disk vector index. It is deliberately simple:
// a flat list of (chunk, vector) entries searched by brute-force cosine. For a
// single repo (a few thousand chunks) this is sub-millisecond and needs no CGO
// database — matching the CGO-free constraint (docs §4). It is NOT concurrency-
// safe; callers own serialization.
type Store struct {
	Dim        int
	Entries    []Entry
	FileHashes map[string]string // relPath -> content hash, for incremental re-embed
}

// IndexPath is where a project's vector index lives — per-project, beside the
// scan results the desktop already watches.
func IndexPath(projectPath string) string {
	return filepath.Join(projectPath, ".trojan", "index", "vectors.gob")
}

// Load reads the index for a project, returning an empty (non-nil) store if none
// exists yet.
func Load(projectPath string) (*Store, error) {
	f, err := os.Open(IndexPath(projectPath))
	if errors.Is(err, os.ErrNotExist) {
		return &Store{FileHashes: map[string]string{}}, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var s Store
	if err := gob.NewDecoder(f).Decode(&s); err != nil {
		return nil, fmt.Errorf("decode index: %w", err)
	}
	if s.FileHashes == nil {
		s.FileHashes = map[string]string{}
	}
	return &s, nil
}

// Save writes the index atomically (temp file + rename) so a crash mid-write
// can't corrupt an existing index.
func (s *Store) Save(projectPath string) error {
	path := IndexPath(projectPath)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "vectors-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op after a successful rename

	if err := gob.NewEncoder(tmp).Encode(s); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

// HashContent returns a stable content hash used to decide whether a file needs
// re-embedding.
func HashContent(content []byte) string {
	sum := sha256.Sum256(content)
	return hex.EncodeToString(sum[:])
}

// NeedsReindex reports whether a file's content differs from what's indexed.
func (s *Store) NeedsReindex(relPath, hash string) bool {
	return s.FileHashes[relPath] != hash
}

// Upsert replaces every entry for relPath with the given entries and records the
// new content hash. This is the incremental unit: re-embed only changed files.
func (s *Store) Upsert(relPath, hash string, entries []Entry) {
	s.removeFile(relPath)
	for _, e := range entries {
		if s.Dim == 0 && len(e.Vector) > 0 {
			s.Dim = len(e.Vector)
		}
		s.Entries = append(s.Entries, e)
	}
	s.FileHashes[relPath] = hash
}

// removeFile drops all entries belonging to relPath (used before re-adding).
func (s *Store) removeFile(relPath string) {
	if _, ok := s.FileHashes[relPath]; !ok {
		return
	}
	kept := s.Entries[:0]
	for _, e := range s.Entries {
		if e.Chunk.FilePath != relPath {
			kept = append(kept, e)
		}
	}
	s.Entries = kept
	delete(s.FileHashes, relPath)
}

// Prune removes entries for files that no longer exist in the given set of
// current relative paths (deletions since the last index).
func (s *Store) Prune(current map[string]bool) {
	for rel := range s.FileHashes {
		if !current[rel] {
			s.removeFile(rel)
		}
	}
}

// Search returns the top-k chunks most similar to query by cosine similarity,
// highest first. Entries whose dimension doesn't match the query are skipped.
func (s *Store) Search(query []float32, k int) ([]Result, error) {
	if len(query) == 0 {
		return nil, errors.New("empty query vector")
	}
	if k <= 0 {
		k = 5
	}
	results := make([]Result, 0, len(s.Entries))
	for _, e := range s.Entries {
		if len(e.Vector) != len(query) {
			continue
		}
		results = append(results, Result{Chunk: e.Chunk, Score: cosine(query, e.Vector)})
	}
	sort.Slice(results, func(i, j int) bool { return results[i].Score > results[j].Score })
	if len(results) > k {
		results = results[:k]
	}
	return results, nil
}

// cosine returns the cosine similarity of two equal-length vectors. Returns 0 if
// either has zero magnitude.
func cosine(a, b []float32) float64 {
	var dot, na, nb float64
	for i := range a {
		av, bv := float64(a[i]), float64(b[i])
		dot += av * bv
		na += av * av
		nb += bv * bv
	}
	if na == 0 || nb == 0 {
		return 0
	}
	return dot / (math.Sqrt(na) * math.Sqrt(nb))
}
