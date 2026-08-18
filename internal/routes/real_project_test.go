package routes

import (
	"os"
	"testing"
)

// TestRealProject runs the resolver against a real project on disk. Gated on
// TROJAN_REAL_PROJECT_DIR so it never runs in CI — a sanity check that extraction
// survives real-world route trees, not just fixtures.
//
//	TROJAN_REAL_PROJECT_DIR=/path/to/app go test ./internal/routes -run TestRealProject -v
func TestRealProject(t *testing.T) {
	dir := os.Getenv("TROJAN_REAL_PROJECT_DIR")
	if dir == "" {
		t.Skip("set TROJAN_REAL_PROJECT_DIR to run against a real project")
	}
	r := NewResolver(dir)
	t.Logf("framework=%q, %d routes extracted", r.Framework(), len(r.Routes()))
	for _, rt := range r.Routes() {
		m := rt.Method
		if m == "" {
			m = "ANY"
		}
		t.Logf("  %-5s %-40s -> %s:%d (%s) guards=%v", m, rt.PathPattern, rt.HandlerFile, rt.HandlerLine, rt.HandlerSymbol, rt.Guards)
	}
	if len(r.Routes()) == 0 {
		t.Errorf("expected to extract at least one route from %s", dir)
	}
}
