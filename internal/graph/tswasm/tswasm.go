// Package tswasm is a minimal, CGO-free binding to tree-sitter, compiled to
// WebAssembly and executed via wazero (github.com/tetratelabs/wazero, a pure
// Go WASM runtime). It exists so internal/graph can extract functions, calls,
// and dangerous-API sinks from JavaScript, TypeScript, and Python source
// without linking the C tree-sitter runtime (which would require CGO and
// break the desktop app's GOOS cross-compile).
//
// The embedded lib/ts.wasm binary is a custom build of tree-sitter's core
// runtime (src/*.c, the same upstream sources tree-sitter ships) with the C,
// C++, JavaScript, Python, and TypeScript grammars compiled in, built with:
//
//	zig cc --target=wasm32-wasi-musl -mexec-model=reactor ...
//
// (see internal/graph/tswasm/BUILD.md for the exact command). Only a small,
// fixed set of tree-sitter's C API is exported from the WASM module: parser
// lifecycle, tree/node navigation by child index, and node type/byte-range
// accessors. That is enough to walk a syntax tree and slice the original
// source bytes for text (see Node.Text), the same style of "walk everything,
// pattern-match on node kind" approach internal/graph's go/ast builder uses,
// just against a generic tree instead of Go's typed AST.
//
// Credit: the wazero-hosted design (an embedded WASM tree-sitter runtime
// exposing malloc/free plus the ts_* C functions as wazero-exported
// functions) follows github.com/malivvan/tree-sitter (MIT licensed), which
// bundles only the C and C++ grammars. This package vendors that same
// approach with our own build that adds JavaScript, Python, and TypeScript.
package tswasm

import (
	"context"
	_ "embed"
	"fmt"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
)

//go:embed lib/ts.wasm
var tsWasm []byte

// Runtime hosts one instantiated copy of the tree-sitter WASM module. Create
// one per BuildFromFiles call (or reuse across calls) and Close it when done;
// it is not safe for concurrent use from multiple goroutines.
type Runtime struct {
	rt wazero.Runtime
	m  api.Module

	malloc api.Function
	free   api.Function

	parserNew         api.Function
	parserDelete      api.Function
	parserSetLanguage api.Function
	parserParseString api.Function

	treeRootNode api.Function

	nodeType            api.Function
	nodeChildCount      api.Function
	nodeNamedChildCount api.Function
	nodeChild           api.Function
	nodeNamedChild      api.Function
	nodeStartByte       api.Function
	nodeEndByte         api.Function
	nodeIsError         api.Function

	languageC          api.Function
	languageCpp        api.Function
	languageJavaScript api.Function
	languagePython     api.Function
	languageTypeScript api.Function
}

// NewRuntime compiles and instantiates the embedded tree-sitter WASM module.
// This does real work (compiling ~6MB of WASM) so callers should reuse one
// Runtime across every non-Go file in a build rather than creating one per
// file.
func NewRuntime(ctx context.Context) (*Runtime, error) {
	rt := wazero.NewRuntime(ctx)

	if _, err := wasi_snapshot_preview1.Instantiate(ctx, rt); err != nil {
		rt.Close(ctx)
		return nil, fmt.Errorf("instantiating wasi: %w", err)
	}

	compiled, err := rt.CompileModule(ctx, tsWasm)
	if err != nil {
		rt.Close(ctx)
		return nil, fmt.Errorf("compiling tree-sitter wasm module: %w", err)
	}

	mod, err := rt.InstantiateModule(ctx, compiled, wazero.NewModuleConfig())
	if err != nil {
		rt.Close(ctx)
		return nil, fmt.Errorf("instantiating tree-sitter wasm module: %w", err)
	}

	get := func(name string) api.Function {
		return mod.ExportedFunction(name)
	}

	return &Runtime{
		rt:     rt,
		m:      mod,
		malloc: get("malloc"),
		free:   get("free"),

		parserNew:         get("ts_parser_new"),
		parserDelete:      get("ts_parser_delete"),
		parserSetLanguage: get("ts_parser_set_language"),
		parserParseString: get("ts_parser_parse_string"),

		treeRootNode: get("ts_tree_root_node"),

		nodeType:            get("ts_node_type"),
		nodeChildCount:      get("ts_node_child_count"),
		nodeNamedChildCount: get("ts_node_named_child_count"),
		nodeChild:           get("ts_node_child"),
		nodeNamedChild:      get("ts_node_named_child"),
		nodeStartByte:       get("ts_node_start_byte"),
		nodeEndByte:         get("ts_node_end_byte"),
		nodeIsError:         get("ts_node_is_error"),

		languageC:          get("tree_sitter_c"),
		languageCpp:        get("tree_sitter_cpp"),
		languageJavaScript: get("tree_sitter_javascript"),
		languagePython:     get("tree_sitter_python"),
		languageTypeScript: get("tree_sitter_typescript"),
	}, nil
}

// Close releases the WASM runtime and everything allocated in its linear
// memory (parsers, trees, nodes). Call it once per Runtime when done.
func (r *Runtime) Close(ctx context.Context) error {
	return r.rt.Close(ctx)
}

// Language wraps a tree-sitter TSLanguage* handle living in WASM memory.
type Language struct{ h uint64 }

func (r *Runtime) language(ctx context.Context, fn api.Function, name string) (Language, error) {
	res, err := fn.Call(ctx)
	if err != nil {
		return Language{}, fmt.Errorf("loading %s grammar: %w", name, err)
	}
	return Language{h: res[0]}, nil
}

// JavaScript returns the tree-sitter-javascript grammar (also used for JSX).
func (r *Runtime) JavaScript(ctx context.Context) (Language, error) {
	return r.language(ctx, r.languageJavaScript, "javascript")
}

// Python returns the tree-sitter-python grammar.
func (r *Runtime) Python(ctx context.Context) (Language, error) {
	return r.language(ctx, r.languagePython, "python")
}

// TypeScript returns the tree-sitter-typescript grammar (TypeScript dialect,
// not TSX; TypeScript's grammar is a superset of JavaScript's for the syntax
// this package cares about (functions, calls, member access).
func (r *Runtime) TypeScript(ctx context.Context) (Language, error) {
	return r.language(ctx, r.languageTypeScript, "typescript")
}

// Tree is a parsed syntax tree. The underlying WASM memory is freed when the
// owning Runtime is closed; Tree itself holds no separate resources to
// release.
type Tree struct {
	r *Runtime
	t uint64
}

// Parse parses src under the given language and returns the resulting tree.
func (r *Runtime) Parse(ctx context.Context, lang Language, src []byte) (Tree, error) {
	if len(src) == 0 {
		// ts_parser_parse_string with a zero-length buffer is well defined,
		// but malloc(0) semantics vary; special-case it and let callers see
		// an empty tree rather than a WASM error.
		src = []byte{0}
	}
	strPtr, err := r.malloc.Call(ctx, uint64(len(src)))
	if err != nil {
		return Tree{}, fmt.Errorf("allocating source buffer: %w", err)
	}
	defer r.free.Call(ctx, strPtr[0]) //nolint:errcheck

	if !r.m.Memory().Write(uint32(strPtr[0]), src) {
		return Tree{}, fmt.Errorf("writing source into wasm memory")
	}

	parserPtr, err := r.parserNew.Call(ctx)
	if err != nil {
		return Tree{}, fmt.Errorf("creating parser: %w", err)
	}
	defer r.parserDelete.Call(ctx, parserPtr[0]) //nolint:errcheck

	ok, err := r.parserSetLanguage.Call(ctx, parserPtr[0], lang.h)
	if err != nil {
		return Tree{}, fmt.Errorf("setting language: %w", err)
	}
	if ok[0] == 0 {
		return Tree{}, fmt.Errorf("incompatible tree-sitter language version")
	}

	treePtr, err := r.parserParseString.Call(ctx, parserPtr[0], uint64(0), strPtr[0], uint64(len(src)))
	if err != nil {
		return Tree{}, fmt.Errorf("parsing source: %w", err)
	}

	return Tree{r: r, t: treePtr[0]}, nil
}

// nodeSize is sizeof(TSNode) in tree-sitter's C ABI, compiled for wasm32
// (4-byte pointers): uint32_t context[4] (16 bytes) + const void *id (4
// bytes) + const TSTree *tree (4 bytes) = 24 bytes.
const nodeSize = 24

func (r *Runtime) allocNode(ctx context.Context) (uint64, error) {
	p, err := r.malloc.Call(ctx, nodeSize)
	if err != nil {
		return 0, fmt.Errorf("allocating node: %w", err)
	}
	return p[0], nil
}

// RootNode returns the tree's root node.
func (t Tree) RootNode(ctx context.Context) (Node, error) {
	nodePtr, err := t.r.allocNode(ctx)
	if err != nil {
		return Node{}, err
	}
	if _, err := t.r.treeRootNode.Call(ctx, nodePtr, t.t); err != nil {
		return Node{}, fmt.Errorf("getting root node: %w", err)
	}
	return Node{r: t.r, ptr: nodePtr}, nil
}

// Node is a handle to one syntax-tree node, still backed by WASM memory.
// Every accessor makes a WASM call, so callers that need a node's text
// should fetch StartByte/EndByte once and slice the original source buffer
// rather than asking tree-sitter to re-render it.
type Node struct {
	r   *Runtime
	ptr uint64
}

// Valid reports whether this Node handle actually refers to a node (a zero
// Node, e.g. from indexing past ChildCount, is not).
func (n Node) Valid() bool { return n.r != nil }

// Kind returns the node's grammar type, e.g. "call_expression", "identifier",
// "function_definition".
func (n Node) Kind(ctx context.Context) (string, error) {
	strPtr, err := n.r.nodeType.Call(ctx, n.ptr)
	if err != nil {
		return "", fmt.Errorf("getting node type: %w", err)
	}
	// ts_node_type returns a NUL-terminated C string; grammar node-type names
	// are static string-table entries with no embedded NUL, so scanning for
	// the terminator is safe and avoids needing strlen exported separately.
	return n.r.readCString(ctx, strPtr[0])
}

func (r *Runtime) readCString(ctx context.Context, ptr uint64) (string, error) {
	const maxLen = 256
	buf, ok := r.m.Memory().Read(uint32(ptr), maxLen)
	if !ok {
		// near the end of memory; fall back to a byte-at-a-time read
		var b []byte
		for i := uint32(0); i < maxLen; i++ {
			c, ok := r.m.Memory().ReadByte(uint32(ptr) + i)
			if !ok || c == 0 {
				break
			}
			b = append(b, c)
		}
		return string(b), nil
	}
	for i, c := range buf {
		if c == 0 {
			return string(buf[:i]), nil
		}
	}
	return string(buf), nil
}

// StartByte returns the byte offset of the node's first byte in the source
// buffer that was parsed.
func (n Node) StartByte(ctx context.Context) (uint32, error) {
	res, err := n.r.nodeStartByte.Call(ctx, n.ptr)
	if err != nil {
		return 0, fmt.Errorf("getting node start byte: %w", err)
	}
	return uint32(res[0]), nil
}

// EndByte returns the byte offset just past the node's last byte.
func (n Node) EndByte(ctx context.Context) (uint32, error) {
	res, err := n.r.nodeEndByte.Call(ctx, n.ptr)
	if err != nil {
		return 0, fmt.Errorf("getting node end byte: %w", err)
	}
	return uint32(res[0]), nil
}

// Text slices the node's byte range out of the original source buffer.
func (n Node) Text(ctx context.Context, src []byte) (string, error) {
	start, err := n.StartByte(ctx)
	if err != nil {
		return "", err
	}
	end, err := n.EndByte(ctx)
	if err != nil {
		return "", err
	}
	if int(end) > len(src) || start > end {
		return "", nil
	}
	return string(src[start:end]), nil
}

// ChildCount returns the number of children, named and anonymous (including
// punctuation and keyword tokens).
func (n Node) ChildCount(ctx context.Context) (uint32, error) {
	res, err := n.r.nodeChildCount.Call(ctx, n.ptr)
	if err != nil {
		return 0, fmt.Errorf("getting child count: %w", err)
	}
	return uint32(res[0]), nil
}

// NamedChildCount returns the number of named (grammar-significant) children,
// excluding anonymous tokens like "(" or "+".
func (n Node) NamedChildCount(ctx context.Context) (uint32, error) {
	res, err := n.r.nodeNamedChildCount.Call(ctx, n.ptr)
	if err != nil {
		return 0, fmt.Errorf("getting named child count: %w", err)
	}
	return uint32(res[0]), nil
}

// Child returns the i'th child (named or not).
func (n Node) Child(ctx context.Context, i uint32) (Node, error) {
	nodePtr, err := n.r.allocNode(ctx)
	if err != nil {
		return Node{}, err
	}
	if _, err := n.r.nodeChild.Call(ctx, nodePtr, n.ptr, uint64(i)); err != nil {
		return Node{}, fmt.Errorf("getting child %d: %w", i, err)
	}
	return Node{r: n.r, ptr: nodePtr}, nil
}

// NamedChild returns the i'th named child.
func (n Node) NamedChild(ctx context.Context, i uint32) (Node, error) {
	nodePtr, err := n.r.allocNode(ctx)
	if err != nil {
		return Node{}, err
	}
	if _, err := n.r.nodeNamedChild.Call(ctx, nodePtr, n.ptr, uint64(i)); err != nil {
		return Node{}, fmt.Errorf("getting named child %d: %w", i, err)
	}
	return Node{r: n.r, ptr: nodePtr}, nil
}

// IsError reports whether this node is a parse-error node. Real-world files
// sometimes fail to parse cleanly (partial edits, unsupported syntax); the
// extraction layer skips subtrees rooted at an error node rather than
// reporting garbage.
func (n Node) IsError(ctx context.Context) (bool, error) {
	res, err := n.r.nodeIsError.Call(ctx, n.ptr)
	if err != nil {
		return false, fmt.Errorf("getting node is-error: %w", err)
	}
	return res[0] != 0, nil
}
