package rag

import (
	"os"
	"path/filepath"
	"testing"
)

// fakeEmbedder returns a deterministic vector per text: a 3-dim vector seeded by
// the text length and its first byte, enough to make search results stable.
type fakeEmbedder struct{ calls int }

func (f *fakeEmbedder) Embed(texts []string, _ string) ([][]float32, error) {
	f.calls++
	out := make([][]float32, len(texts))
	for i, t := range texts {
		var first float32
		if len(t) > 0 {
			first = float32(t[0])
		}
		out[i] = []float32{float32(len(t)), first, 1}
	}
	return out, nil
}

func writeFile(t *testing.T, dir, rel, content string) string {
	t.Helper()
	p := filepath.Join(dir, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestIndexProject_IncrementalAndPrune(t *testing.T) {
	dir := t.TempDir()
	a := writeFile(t, dir, "a.go", "package main\nfunc A() {}\n")
	b := writeFile(t, dir, "b.go", "package main\nfunc B() {}\n")

	emb := &fakeEmbedder{}
	ix := &Indexer{Embedder: emb}

	// First pass indexes both.
	stats, err := ix.IndexProject(dir, []string{a, b})
	if err != nil {
		t.Fatal(err)
	}
	if stats.FilesIndexed != 2 {
		t.Errorf("first pass: FilesIndexed = %d, want 2", stats.FilesIndexed)
	}
	if stats.ChunksAdded < 2 {
		t.Errorf("first pass: ChunksAdded = %d, want >= 2", stats.ChunksAdded)
	}

	// Second pass, nothing changed -> all skipped, no embed call.
	callsBefore := emb.calls
	stats, err = ix.IndexProject(dir, []string{a, b})
	if err != nil {
		t.Fatal(err)
	}
	if stats.FilesIndexed != 0 || stats.FilesSkipped != 2 {
		t.Errorf("second pass: indexed=%d skipped=%d, want 0/2", stats.FilesIndexed, stats.FilesSkipped)
	}
	if emb.calls != callsBefore {
		t.Errorf("second pass should not call embedder (nothing changed)")
	}

	// Modify a.go -> only it re-embeds.
	writeFile(t, dir, "a.go", "package main\nfunc A() { x := 1; _ = x }\n")
	stats, _ = ix.IndexProject(dir, []string{a, b})
	if stats.FilesIndexed != 1 || stats.FilesSkipped != 1 {
		t.Errorf("after edit: indexed=%d skipped=%d, want 1/1", stats.FilesIndexed, stats.FilesSkipped)
	}

	// Drop b.go from the file set -> it's pruned.
	stats, _ = ix.IndexProject(dir, []string{a})
	if stats.FilesPruned != 1 {
		t.Errorf("FilesPruned = %d, want 1", stats.FilesPruned)
	}
	store, _ := Load(dir)
	if _, ok := store.FileHashes["b.go"]; ok {
		t.Error("b.go should have been pruned from the index")
	}
}

func TestRetrieve(t *testing.T) {
	dir := t.TempDir()
	a := writeFile(t, dir, "a.go", "package main\nfunc Login() {}\n")
	emb := &fakeEmbedder{}
	ix := &Indexer{Embedder: emb}
	if _, err := ix.IndexProject(dir, []string{a}); err != nil {
		t.Fatal(err)
	}

	r, err := NewRetriever(dir, emb)
	if err != nil {
		t.Fatal(err)
	}
	res, err := r.Retrieve("func Login() {}", 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(res) == 0 {
		t.Fatal("expected at least one retrieved chunk")
	}
	if res[0].Chunk.FilePath != "a.go" {
		t.Errorf("expected chunk from a.go, got %s", res[0].Chunk.FilePath)
	}
}

func TestRetrieveEmptyIndex(t *testing.T) {
	dir := t.TempDir()
	r, err := NewRetriever(dir, &fakeEmbedder{})
	if err != nil {
		t.Fatal(err)
	}
	res, err := r.Retrieve("anything", 5)
	if err != nil {
		t.Errorf("empty index should not error, got %v", err)
	}
	if res != nil {
		t.Errorf("empty index should return nil results, got %v", res)
	}
}
