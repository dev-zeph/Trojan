package graph

import (
	"context"
	"sort"

	"github.com/dev-zeph/trojan/internal/graph/tswasm"
)

// tsFile holds the per-file state the tree-sitter based builders (JS/TS,
// Python) share: the source bytes (for Text() slicing and line lookup) and a
// precomputed newline index so byte offsets can be turned into 1-based line
// numbers without rescanning the file for every node.
type tsFile struct {
	path       string
	src        []byte
	newlineIdx []int // byte offsets of every '\n' in src, ascending
}

func newTSFile(path string, src []byte) *tsFile {
	f := &tsFile{path: path, src: src}
	for i, b := range src {
		if b == '\n' {
			f.newlineIdx = append(f.newlineIdx, i)
		}
	}
	return f
}

// line returns the 1-based line number containing byte offset pos.
func (f *tsFile) line(pos uint32) int {
	// number of newlines strictly before pos, +1.
	n := sort.Search(len(f.newlineIdx), func(i int) bool { return f.newlineIdx[i] >= int(pos) })
	return n + 1
}

func (f *tsFile) text(ctx context.Context, n tswasm.Node) string {
	s, err := n.Text(ctx, f.src)
	if err != nil {
		return ""
	}
	return s
}

// namedChildren returns every named child of n, in order. Named children
// exclude anonymous tokens (punctuation, keywords), which is what every
// extraction pass in this package wants: it walks grammar-significant
// structure, not source formatting.
func namedChildren(ctx context.Context, n tswasm.Node) ([]tswasm.Node, error) {
	count, err := n.NamedChildCount(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]tswasm.Node, 0, count)
	for i := uint32(0); i < count; i++ {
		c, err := n.NamedChild(ctx, i)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, nil
}

// allChildren returns every child of n, named or anonymous. Only used where
// an anonymous token itself matters, e.g. reading the operator out of a
// binary expression ("left + right", "+" is not a named node).
func allChildren(ctx context.Context, n tswasm.Node) ([]tswasm.Node, error) {
	count, err := n.ChildCount(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]tswasm.Node, 0, count)
	for i := uint32(0); i < count; i++ {
		c, err := n.Child(ctx, i)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, nil
}

// findByKind returns the first node in ns whose grammar kind is in kinds.
// Extraction below searches by kind rather than fixed child index because
// TypeScript's grammar interleaves extra named children (type annotations,
// type parameters) into shapes JavaScript keeps simple, so a positional index
// that works for `function foo() {}` breaks for `function foo(): void {}`.
func findByKind(ctx context.Context, ns []tswasm.Node, kinds map[string]bool) (tswasm.Node, bool) {
	for _, n := range ns {
		k, err := n.Kind(ctx)
		if err != nil {
			continue
		}
		if kinds[k] {
			return n, true
		}
	}
	return tswasm.Node{}, false
}

// attrName returns the last named child's text of a member-access node: the
// ".prop" part of a JS member_expression (object, property) or the ".attr"
// part of a Python attribute (object, attribute). Both grammars shape member
// access the same way (object first, accessed name last), so one helper
// covers both.
func attrName(ctx context.Context, f *tsFile, n tswasm.Node) string {
	nc, err := namedChildren(ctx, n)
	if err != nil || len(nc) == 0 {
		return ""
	}
	return f.text(ctx, nc[len(nc)-1])
}

// pendingCallEdge is a same-file call site whose callee is resolved once
// every function in the file has been registered, mirroring build.go's
// two-pass approach for Go (register everything, then wire calls by name).
type pendingCallEdge struct {
	callerID int
	callee   string
}

// isStringLiteralKind reports whether a node kind is a plain string literal
// in the JS or Python grammars, used to tell "a" + "b" (harmless constant
// folding) apart from "SELECT ... " + userInput (injection).
func isStringLiteralKind(kind string) bool {
	return kind == "string" || kind == "template_string" || kind == "concatenated_string"
}

// hasUnsafeConcat walks an argument's subtree looking for a binary "+" (JS)
// or binary_operator "+" (Python) where at least one operand is not a plain
// string literal (the shape of an interpolated query or command). It mirrors
// build.go's hasStringConcat/isBasicLit check for the Go path.
func hasUnsafeConcat(ctx context.Context, n tswasm.Node) bool {
	kind, err := n.Kind(ctx)
	if err != nil {
		return false
	}
	if kind == "binary_expression" || kind == "binary_operator" {
		kids, err := allChildren(ctx, n)
		if err == nil && len(kids) >= 3 {
			opText := ""
			for _, k := range kids {
				kk, _ := k.Kind(ctx)
				// the operator is the anonymous token between the two named
				// operands; named nodes have grammar kinds like "identifier"
				// or "string", the operator's kind equals its own text ("+").
				if kk == "+" {
					opText = "+"
					break
				}
			}
			if opText == "+" {
				left, right := kids[0], kids[len(kids)-1]
				lk, _ := left.Kind(ctx)
				rk, _ := right.Kind(ctx)
				if !isStringLiteralKind(lk) || !isStringLiteralKind(rk) {
					return true
				}
			}
		}
	}
	// recurse into named children: the concatenation can be nested inside a
	// call, a template substitution, parentheses, etc.
	kids, err := namedChildren(ctx, n)
	if err != nil {
		return false
	}
	for _, k := range kids {
		if hasUnsafeConcat(ctx, k) {
			return true
		}
	}
	return false
}
