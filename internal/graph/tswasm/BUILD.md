# Building lib/ts.wasm

`lib/ts.wasm` is tree-sitter's core runtime plus five grammars (C, C++,
JavaScript, Python, TypeScript) compiled to a single WASI-reactor WASM
module with [zig](https://ziglang.org/) (`zig cc`, no CGO, no C toolchain
other than zig's bundled clang+lld). It is based on
[github.com/malivvan/tree-sitter](https://github.com/malivvan/tree-sitter)
(MIT licensed), which ships the same runtime with only C and C++ built in;
this build adds the JavaScript, Python, and TypeScript grammar sources from
that same repository's `src/` tree and exports their entry points too.

To rebuild (only needed to add a grammar or pick up an upstream tree-sitter
update):

```sh
# go get github.com/malivvan/tree-sitter@latest once, to refresh src/*.c from
# upstream, then compile from its module cache directory (or a local copy):
SRC=$(go env GOMODCACHE)/github.com/malivvan/tree-sitter@<version>/src

zig cc --target=wasm32-wasi-musl -mexec-model=reactor -I "$SRC" "$SRC/lib.c" \
    "$SRC/c/parser.c" \
    "$SRC/cpp/parser.c" "$SRC/cpp/scanner.c" \
    "$SRC/javascript/parser.c" "$SRC/javascript/scanner.c" \
    "$SRC/python/parser.c" "$SRC/python/scanner.c" \
    "$SRC/typescript/typescript/parser.c" "$SRC/typescript/typescript/scanner.c" \
    -o lib/ts.wasm -Os -fPIC -Wl,--no-entry -Wl,-z -Wl,stack-size=131072 -Wl,--strip-debug \
    -Wl,--import-symbols \
    -Wl,--export=malloc -Wl,--export=free -Wl,--export=strlen \
    -Wl,--export=ts_parser_new -Wl,--export=ts_parser_parse_string \
    -Wl,--export=ts_parser_set_language -Wl,--export=ts_parser_delete \
    -Wl,--export=ts_language_version -Wl,--export=ts_tree_root_node \
    -Wl,--export=ts_node_string -Wl,--export=ts_node_child_count \
    -Wl,--export=ts_node_named_child_count -Wl,--export=ts_node_child \
    -Wl,--export=ts_node_named_child -Wl,--export=ts_node_type \
    -Wl,--export=ts_node_start_byte -Wl,--export=ts_node_end_byte \
    -Wl,--export=ts_node_is_error \
    -Wl,--export=tree_sitter_c -Wl,--export=tree_sitter_cpp \
    -Wl,--export=tree_sitter_javascript -Wl,--export=tree_sitter_python \
    -Wl,--export=tree_sitter_typescript
```

Install zig with `brew install zig` (or see ziglang.org for other
platforms). Verify the grammars actually landed in the binary with:

```sh
strings lib/ts.wasm | grep -o 'tree_sitter_[a-z_]*' | sort -u
# tree_sitter_c
# tree_sitter_cpp
# tree_sitter_javascript
# tree_sitter_python
# tree_sitter_typescript
```

## Adding another grammar

1. Add its `parser.c` (and `scanner.c` if it has an external scanner) to the
   `zig cc` command's source list and its `tree_sitter_<name>` symbol to the
   `--export` list.
2. Add a loader method to `Runtime` in `tswasm.go` (`languageX
   api.Function`, wired to `mod.ExportedFunction("tree_sitter_x")` in
   `NewRuntime`, exposed as an `X(ctx) (Language, error)` method) following
   the `JavaScript`/`Python`/`TypeScript` pattern.
3. Add a `buildFromXFiles` extraction pass in `internal/graph` (see
   `build_javascript.go` and `build_py.go`) and route its extensions to it
   in `dispatch.go`'s `BuildFromFiles`.

Every grammar's external-scanner functions are prefixed
`tree_sitter_<grammar>_external_scanner_*`, so grammars don't collide when
compiled into one binary; this is why the single-module approach scales to
many languages without per-language WASM files or dynamic linking.
