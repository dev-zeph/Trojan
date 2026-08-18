// Package rag provides Trojan's local, CGO-free code retrieval: chunking source
// into embeddable units and a flat-file vector store with brute-force cosine
// nearest-neighbour search. Embeddings themselves are produced server-side by
// the `embed` edge function (keys never touch the binary); this package only
// prepares chunk text and stores/searches the vectors that come back.
//
// Everything here is pure Go — no CGO — to preserve the GOOS=… cross-compile the
// desktop app relies on (docs/trojan-agentic-implementation.md §1).
package rag

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
)

// Chunk is one embeddable unit of source: a symbol (Go) or a line window (other
// languages), anchored back to its file and line span so retrieval can cite
// file:line and callers can pull the exact region.
type Chunk struct {
	FilePath  string `json:"file_path"`
	StartLine int    `json:"start_line"` // 1-indexed, inclusive
	EndLine   int    `json:"end_line"`   // 1-indexed, inclusive
	Symbol    string `json:"symbol,omitempty"`
	Text      string `json:"text"`
}

const (
	// windowLines / windowOverlap size the sliding window used for non-Go
	// languages. Overlap keeps a construct that straddles a boundary intact in
	// at least one chunk.
	windowLines   = 60
	windowOverlap = 15
	// maxChunkLines caps a single Go declaration; larger ones are windowed so a
	// giant function doesn't become one unwieldy embedding.
	maxChunkLines = 120
)

// ChunkFile splits a source file into chunks. Go files are chunked by top-level
// declaration via go/parser (precise, symbol-anchored); every other language
// uses an overlapping line window. A Go file that fails to parse falls back to
// windowing, so partial/broken sources still index.
func ChunkFile(path string, content []byte) []Chunk {
	if len(content) == 0 {
		return nil
	}
	lines := strings.Split(string(content), "\n")
	// Drop the phantom empty element produced when a file ends in a newline, so
	// chunk line spans line up with real 1-indexed file lines.
	if n := len(lines); n > 1 && lines[n-1] == "" {
		lines = lines[:n-1]
	}
	if strings.EqualFold(filepath.Ext(path), ".go") {
		if chunks, ok := chunkGo(path, content, lines); ok {
			return chunks
		}
	}
	return chunkWindow(path, lines)
}

// chunkGo produces one chunk per top-level declaration (func, type, var, const).
// ok is false on a parse error so the caller can fall back to windowing.
func chunkGo(path string, content []byte, lines []string) (chunks []Chunk, ok bool) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "", content, parser.SkipObjectResolution)
	if err != nil || file == nil {
		return nil, false
	}
	for _, d := range file.Decls {
		start := fset.Position(d.Pos()).Line
		end := fset.Position(d.End()).Line
		if start < 1 || end > len(lines) || end < start {
			continue
		}
		sym := declSymbol(d)
		if end-start+1 > maxChunkLines {
			// Window oversized declarations, preserving the symbol name.
			for _, c := range chunkWindowRange(path, lines, start, end) {
				c.Symbol = sym
				chunks = append(chunks, c)
			}
			continue
		}
		chunks = append(chunks, Chunk{
			FilePath:  path,
			StartLine: start,
			EndLine:   end,
			Symbol:    sym,
			Text:      strings.Join(lines[start-1:end], "\n"),
		})
	}
	if len(chunks) == 0 {
		return nil, false // e.g. a file with only a package clause — window it
	}
	return chunks, true
}

// declSymbol returns a human-readable name for a top-level declaration, used to
// label its chunk (e.g. "func Login", "type User"). Empty when there's no single
// meaningful name (e.g. a grouped var block).
func declSymbol(d ast.Decl) string {
	switch decl := d.(type) {
	case *ast.FuncDecl:
		if decl.Name != nil {
			return "func " + decl.Name.Name
		}
	case *ast.GenDecl:
		if len(decl.Specs) == 1 {
			switch spec := decl.Specs[0].(type) {
			case *ast.TypeSpec:
				if spec.Name != nil {
					return "type " + spec.Name.Name
				}
			case *ast.ValueSpec:
				if len(spec.Names) > 0 {
					return decl.Tok.String() + " " + spec.Names[0].Name
				}
			}
		}
	}
	return ""
}

// chunkWindow slides an overlapping fixed-size window over the whole file.
func chunkWindow(path string, lines []string) []Chunk {
	return chunkWindowRange(path, lines, 1, len(lines))
}

// chunkWindowRange windows the 1-indexed inclusive [from, to] line range.
func chunkWindowRange(path string, lines []string, from, to int) []Chunk {
	var chunks []Chunk
	step := windowLines - windowOverlap
	if step < 1 {
		step = windowLines
	}
	for start := from; start <= to; start += step {
		end := min(start+windowLines-1, to)
		text := strings.Join(lines[start-1:end], "\n")
		if strings.TrimSpace(text) != "" {
			chunks = append(chunks, Chunk{
				FilePath:  path,
				StartLine: start,
				EndLine:   end,
				Text:      text,
			})
		}
		if end == to {
			break
		}
	}
	return chunks
}
