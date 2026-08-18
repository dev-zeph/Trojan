package rag

import (
	"testing"
)

func vec(f ...float32) []float32 { return f }

func TestStoreSearchRanksByCosine(t *testing.T) {
	s := &Store{FileHashes: map[string]string{}}
	s.Upsert("a.go", "h1", []Entry{
		{Chunk: Chunk{FilePath: "a.go", Symbol: "func A"}, Vector: vec(1, 0, 0)},
		{Chunk: Chunk{FilePath: "a.go", Symbol: "func B"}, Vector: vec(0, 1, 0)},
	})
	s.Upsert("b.go", "h2", []Entry{
		{Chunk: Chunk{FilePath: "b.go", Symbol: "func C"}, Vector: vec(0.9, 0.1, 0)},
	})

	res, err := s.Search(vec(1, 0, 0), 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 3 {
		t.Fatalf("expected 3 results, got %d", len(res))
	}
	if res[0].Chunk.Symbol != "func A" {
		t.Errorf("closest should be func A, got %s (score %.3f)", res[0].Chunk.Symbol, res[0].Score)
	}
	if res[1].Chunk.Symbol != "func C" {
		t.Errorf("second should be func C (0.9,0.1,0), got %s", res[1].Chunk.Symbol)
	}
	if res[0].Score < res[1].Score || res[1].Score < res[2].Score {
		t.Errorf("results not sorted descending: %.3f %.3f %.3f", res[0].Score, res[1].Score, res[2].Score)
	}
}

func TestStoreTopK(t *testing.T) {
	s := &Store{FileHashes: map[string]string{}}
	entries := []Entry{}
	for i := 0; i < 10; i++ {
		entries = append(entries, Entry{Chunk: Chunk{FilePath: "a.go"}, Vector: vec(float32(i), 1, 0)})
	}
	s.Upsert("a.go", "h", entries)
	res, _ := s.Search(vec(1, 0, 0), 3)
	if len(res) != 3 {
		t.Fatalf("expected top-3, got %d", len(res))
	}
}

func TestStoreIncrementalUpsert(t *testing.T) {
	s := &Store{FileHashes: map[string]string{}}
	s.Upsert("a.go", "h1", []Entry{{Chunk: Chunk{FilePath: "a.go", Symbol: "old"}, Vector: vec(1, 0)}})
	if !s.NeedsReindex("a.go", "h2") {
		t.Error("changed hash should need reindex")
	}
	if s.NeedsReindex("a.go", "h1") {
		t.Error("same hash should not need reindex")
	}
	// Re-upsert replaces, doesn't duplicate.
	s.Upsert("a.go", "h2", []Entry{{Chunk: Chunk{FilePath: "a.go", Symbol: "new"}, Vector: vec(1, 0)}})
	if len(s.Entries) != 1 {
		t.Fatalf("expected 1 entry after replace, got %d", len(s.Entries))
	}
	if s.Entries[0].Chunk.Symbol != "new" {
		t.Errorf("expected replaced entry, got %s", s.Entries[0].Chunk.Symbol)
	}
}

func TestStorePrune(t *testing.T) {
	s := &Store{FileHashes: map[string]string{}}
	s.Upsert("a.go", "h", []Entry{{Chunk: Chunk{FilePath: "a.go"}, Vector: vec(1)}})
	s.Upsert("b.go", "h", []Entry{{Chunk: Chunk{FilePath: "b.go"}, Vector: vec(1)}})
	s.Prune(map[string]bool{"a.go": true}) // b.go deleted
	if _, ok := s.FileHashes["b.go"]; ok {
		t.Error("b.go should be pruned")
	}
	if len(s.Entries) != 1 || s.Entries[0].Chunk.FilePath != "a.go" {
		t.Errorf("expected only a.go entry, got %+v", s.Entries)
	}
}

func TestStoreSaveLoadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	s := &Store{FileHashes: map[string]string{}}
	s.Upsert("a.go", "h", []Entry{{Chunk: Chunk{FilePath: "a.go", Symbol: "func A", StartLine: 1, EndLine: 3}, Vector: vec(0.1, 0.2, 0.3)}})
	if err := s.Save(dir); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Dim != 3 {
		t.Errorf("dim = %d, want 3", loaded.Dim)
	}
	if len(loaded.Entries) != 1 || loaded.Entries[0].Chunk.Symbol != "func A" {
		t.Fatalf("round-trip lost entry: %+v", loaded.Entries)
	}
	if loaded.FileHashes["a.go"] != "h" {
		t.Errorf("round-trip lost hash: %v", loaded.FileHashes)
	}
}

func TestLoadMissingReturnsEmpty(t *testing.T) {
	s, err := Load(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if s == nil || len(s.Entries) != 0 || s.FileHashes == nil {
		t.Errorf("expected empty non-nil store, got %+v", s)
	}
}
