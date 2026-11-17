package graph

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fileWriteSinkLines returns the 1-based lines of file-op (path-traversal) sinks
// on a built single-file graph.
func fileWriteSinkLines(t *testing.T, src string) []int {
	t.Helper()
	dir := t.TempDir()
	f := filepath.Join(dir, "config.js")
	if err := os.WriteFile(f, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	g, err := BuildFromFiles([]string{f})
	if err != nil {
		t.Fatal(err)
	}
	var lines []int
	for _, n := range g.Nodes {
		if n.Kind == KindSink && strings.Contains(n.SinkRule, "path traversal") {
			lines = append(lines, n.Line)
		}
	}
	return lines
}

// TestFileWriteConstantPathNotFlagged mirrors ashgrove-portal lib/config.js:15:
// a write to a constant, config-derived path cannot be steered by an attacker,
// so it must not be a path-traversal sink (and so cannot fan out as a finding
// across every route that requires the module at init time).
func TestFileWriteConstantPathNotFlagged(t *testing.T) {
	src := "const fs = require(\"node:fs\");\n" +
		"const path = require(\"node:path\");\n" +
		"const DATA_DIR = path.join(__dirname, \"..\", \"data\");\n" +
		"function loadSessionKey() {\n" +
		"  const file = path.join(DATA_DIR, \".session-key\");\n" +
		"  const key = \"abc\";\n" +
		"  fs.writeFileSync(file, key, { mode: 0o600 });\n" +
		"  return key;\n" +
		"}\n"
	if lines := fileWriteSinkLines(t, src); len(lines) != 0 {
		t.Errorf("constant-path file write flagged as path traversal at lines %v (false positive)", lines)
	}
}

// TestFileWriteRequestPathStillFlagged is the preservation check: a write whose
// path is derived from the request is a real traversal risk and must stay.
func TestFileWriteRequestPathStillFlagged(t *testing.T) {
	src := "const fs = require(\"node:fs\");\n" +
		"const path = require(\"node:path\");\n" +
		"router.post(\"/upload\", (req, res) => {\n" +
		"  const name = String(req.body.name || \"\");\n" +
		"  fs.writeFileSync(path.join(\"/data\", name), req.body.content);\n" +
		"});\n"
	if lines := fileWriteSinkLines(t, src); len(lines) == 0 {
		t.Error("request-derived file-write path must still be flagged as path traversal")
	}
}
