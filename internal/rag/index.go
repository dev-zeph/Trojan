package rag

import (
	"fmt"
	"os"
	"path/filepath"
)

// Embedder turns texts into vectors. It's injected so the indexer and retriever
// are testable without the network and provider-agnostic: production wires it to
// the `embed` edge function (internal/ai.EmbedTexts), tests use a fake. inputType
// is "document" when indexing source, "query" when searching.
type Embedder interface {
	Embed(texts []string, inputType string) ([][]float32, error)
}

// IndexStats summarizes an indexing pass.
type IndexStats struct {
	FilesIndexed int // files (re)embedded this pass
	FilesSkipped int // unchanged since last index
	ChunksAdded  int
	FilesPruned  int // indexed files that no longer exist
}

// Indexer builds and incrementally updates a repository's vector index. This is
// the shared code-context service (docs §4): triage RAG today, the §6.6 grey-box
// brain later, all query the same store.
type Indexer struct {
	Embedder Embedder
}

// IndexProject (re)indexes the given source files under projectPath. Only files
// whose content changed since the last pass are re-embedded; files previously
// indexed but absent from `files` are pruned. The store is persisted before
// returning. `files` are absolute paths; the store keys chunks by path relative
// to projectPath so the index is portable across machines/checkouts.
func (ix *Indexer) IndexProject(projectPath string, files []string) (IndexStats, error) {
	store, err := Load(projectPath)
	if err != nil {
		return IndexStats{}, err
	}

	var stats IndexStats
	current := make(map[string]bool, len(files))

	// Gather chunks for changed files, then embed them all in one call so
	// EmbedTexts batches optimally across files.
	type pending struct {
		rel    string
		hash   string
		chunks []Chunk
	}
	var toEmbed []pending
	var allTexts []string

	for _, abs := range files {
		content, err := os.ReadFile(abs)
		if err != nil {
			continue // unreadable file — skip, don't fail the whole index
		}
		rel := relPath(projectPath, abs)
		current[rel] = true
		hash := HashContent(content)
		if !store.NeedsReindex(rel, hash) {
			stats.FilesSkipped++
			continue
		}
		chunks := ChunkFile(rel, content)
		if len(chunks) == 0 {
			// File is now empty/unchunkable: drop stale entries, record hash.
			store.Upsert(rel, hash, nil)
			continue
		}
		toEmbed = append(toEmbed, pending{rel: rel, hash: hash, chunks: chunks})
		for _, c := range chunks {
			allTexts = append(allTexts, c.Text)
		}
	}

	if len(allTexts) > 0 {
		vecs, err := ix.Embedder.Embed(allTexts, "document")
		if err != nil {
			return stats, err
		}
		if len(vecs) != len(allTexts) {
			return stats, fmt.Errorf("embed returned %d vectors for %d chunks", len(vecs), len(allTexts))
		}
		// Slice vectors back to their files in the order they were collected.
		vi := 0
		for _, p := range toEmbed {
			entries := make([]Entry, len(p.chunks))
			for i, c := range p.chunks {
				entries[i] = Entry{Chunk: c, Vector: vecs[vi]}
				vi++
			}
			store.Upsert(p.rel, p.hash, entries)
			stats.FilesIndexed++
			stats.ChunksAdded += len(entries)
		}
	}

	before := len(store.FileHashes)
	store.Prune(current)
	stats.FilesPruned = before - len(store.FileHashes)

	if err := store.Save(projectPath); err != nil {
		return stats, err
	}
	return stats, nil
}

// Retriever answers similarity queries against a loaded store.
type Retriever struct {
	Embedder Embedder
	Store    *Store
}

// NewRetriever loads the project's index for querying.
func NewRetriever(projectPath string, e Embedder) (*Retriever, error) {
	s, err := Load(projectPath)
	if err != nil {
		return nil, err
	}
	return &Retriever{Embedder: e, Store: s}, nil
}

// Retrieve embeds the query and returns the top-k most similar code chunks.
// Returns nil (no error) when the index is empty, so callers degrade to
// structural context rather than failing.
func (r *Retriever) Retrieve(query string, k int) ([]Result, error) {
	if len(r.Store.Entries) == 0 {
		return nil, nil
	}
	vecs, err := r.Embedder.Embed([]string{query}, "query")
	if err != nil {
		return nil, err
	}
	if len(vecs) == 0 {
		return nil, nil
	}
	return r.Store.Search(vecs[0], k)
}

func relPath(base, abs string) string {
	if rel, err := filepath.Rel(base, abs); err == nil {
		return filepath.ToSlash(rel)
	}
	return filepath.ToSlash(abs)
}
