package rag

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func TestWalkSource(t *testing.T) {
	dir := t.TempDir()
	mk := func(rel string) {
		p := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// Should be indexed.
	mk("main.go")
	mk("src/api/users.ts")
	mk("app/handlers/auth.py")
	// Should be skipped.
	mk("node_modules/react/index.js")
	mk("dist/bundle.js")
	mk("src/api/users.test.ts")
	mk("internal/foo_test.go")
	mk(".git/config")
	mk("README.md")     // not a source extension
	mk("config.json")   // not a source extension

	got, err := WalkSource(dir)
	if err != nil {
		t.Fatal(err)
	}
	var rels []string
	for _, g := range got {
		rel, _ := filepath.Rel(dir, g)
		rels = append(rels, filepath.ToSlash(rel))
	}
	sort.Strings(rels)
	want := []string{"app/handlers/auth.py", "main.go", "src/api/users.ts"}
	if strings.Join(rels, ",") != strings.Join(want, ",") {
		t.Errorf("WalkSource =\n  %v\nwant\n  %v", rels, want)
	}
}

func TestWalkSourceSkipsOversized(t *testing.T) {
	dir := t.TempDir()
	big := filepath.Join(dir, "huge.js")
	if err := os.WriteFile(big, make([]byte, maxIndexFileBytes+1), 0o644); err != nil {
		t.Fatal(err)
	}
	small := filepath.Join(dir, "ok.js")
	if err := os.WriteFile(small, []byte("const x = 1"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := WalkSource(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || filepath.Base(got[0]) != "ok.js" {
		t.Errorf("expected only ok.js, got %v", got)
	}
}
