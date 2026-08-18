package rag

import (
	"strings"
	"testing"
)

func TestChunkFile_Go(t *testing.T) {
	src := `package main

import "fmt"

func Login(u string) bool {
	return u == "admin"
}

type User struct {
	Name string
}
`
	chunks := ChunkFile("auth.go", []byte(src))
	if len(chunks) == 0 {
		t.Fatal("expected chunks, got none")
	}
	var gotLogin, gotUser bool
	for _, c := range chunks {
		if c.Symbol == "func Login" {
			gotLogin = true
			if !strings.Contains(c.Text, `return u == "admin"`) {
				t.Errorf("Login chunk missing body: %s", c.Text)
			}
		}
		if c.Symbol == "type User" {
			gotUser = true
		}
		if c.StartLine < 1 || c.EndLine < c.StartLine {
			t.Errorf("bad line span on chunk %+v", c)
		}
	}
	if !gotLogin || !gotUser {
		t.Errorf("expected func Login and type User chunks; got %+v", chunks)
	}
}

func TestChunkFile_GoParseErrorFallsBackToWindow(t *testing.T) {
	// Broken Go must still produce chunks (windowed), never zero.
	src := "package main\nfunc broken( {\n\tx := 1\n"
	chunks := ChunkFile("broken.go", []byte(src))
	if len(chunks) == 0 {
		t.Fatal("expected windowed fallback chunks, got none")
	}
	if chunks[0].Symbol != "" {
		t.Errorf("windowed chunk should have no symbol, got %q", chunks[0].Symbol)
	}
}

func TestChunkFile_WindowNonGo(t *testing.T) {
	var b strings.Builder
	for i := 0; i < 150; i++ {
		b.WriteString("const x")
		b.WriteString(strings.Repeat("y", 1)) // keep lines non-blank
		b.WriteString(" = ")
		b.WriteByte('0' + byte(i%10))
		b.WriteByte('\n')
	}
	chunks := ChunkFile("app.js", []byte(b.String()))
	if len(chunks) < 2 {
		t.Fatalf("expected multiple windows for 150 lines, got %d", len(chunks))
	}
	// Windows should overlap: chunk 2 starts before chunk 1 ends.
	if chunks[1].StartLine > chunks[0].EndLine {
		t.Errorf("expected overlapping windows: c0 ends %d, c1 starts %d", chunks[0].EndLine, chunks[1].StartLine)
	}
	// Full coverage: last chunk reaches the final line.
	if last := chunks[len(chunks)-1]; last.EndLine != 150 {
		t.Errorf("expected coverage to line 150, last chunk ends %d", last.EndLine)
	}
}

func TestChunkFile_Empty(t *testing.T) {
	if got := ChunkFile("x.go", nil); got != nil {
		t.Errorf("empty content should yield nil, got %v", got)
	}
}
