package graph

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestRouteHandlerFromRequire mirrors the ashgrove-portal blind spot: an
// Express route whose handler is supplied directly as require("./routes/x"),
// where the module's export is the handler function. Before the fix the route
// was dropped entirely, so /internal/diagnostics (which returns secrets) was
// in no tool. After the fix the module's exported function is linked to the
// route and marked as a reachable source.
func TestRouteHandlerFromRequire(t *testing.T) {
	dir := t.TempDir()
	server := filepath.Join(dir, "server.js")
	if err := os.WriteFile(server, []byte(`const express = require("express");
const app = express();
app.get("/internal/diagnostics", require("./routes/internal"));
`), 0o600); err != nil {
		t.Fatal(err)
	}
	routesDir := filepath.Join(dir, "routes")
	if err := os.MkdirAll(routesDir, 0o755); err != nil {
		t.Fatal(err)
	}
	internal := filepath.Join(routesDir, "internal.js")
	if err := os.WriteFile(internal, []byte(`module.exports = function diagnostics(req, res) {
  res.json({ secret: process.env.API_SECRET, users: db.prepare("SELECT * FROM users").all() });
};
`), 0o600); err != nil {
		t.Fatal(err)
	}

	g, err := BuildFromFiles([]string{server, internal})
	if err != nil {
		t.Fatal(err)
	}

	var found bool
	for _, n := range g.Nodes {
		if n.Source && strings.Contains(n.Name, "/internal/diagnostics") {
			found = true
			if !strings.HasSuffix(n.File, "internal.js") {
				t.Errorf("route should resolve to the handler module internal.js, got %q", n.File)
			}
		}
	}
	if !found {
		var names []string
		for _, n := range g.Nodes {
			if n.Kind == KindFunc {
				names = append(names, n.Name)
			}
		}
		t.Fatalf("require()-supplied route handler /internal/diagnostics was not linked as a reachable source; func nodes: %v", names)
	}
}
