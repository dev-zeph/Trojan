package graph

import (
	"os"
	"path/filepath"
	"testing"
)

// TestPaths_FindsSourceToSink proves the core thesis on a small vulnerable
// sample: an HTTP handler (source) reaches a SQL sink through a helper, and the
// path is reported with the injection escalated to high severity and PII flagged.
func TestPaths_FindsSourceToSink(t *testing.T) {
	src := `package api

import (
	"net/http"
	"database/sql"
)

var db *sql.DB

// HandleUser is the untrusted entrypoint.
func HandleUser(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	lookup(id)
}

// lookup builds a query by concatenation — the classic injection.
func lookup(id string) {
	email := "x"
	_, _ = db.Query("SELECT * FROM users WHERE id = " + id)
	_ = email
}
`
	dir := t.TempDir()
	f := filepath.Join(dir, "api.go")
	if err := os.WriteFile(f, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}

	g, err := BuildFromGoFiles([]string{f})
	if err != nil {
		t.Fatalf("build: %v", err)
	}

	paths := g.Paths()
	if len(paths) == 0 {
		t.Fatal("expected at least one source->sink path, got none")
	}

	var found bool
	for _, p := range paths {
		if p.Source.Name == "api.HandleUser" && p.Severity == "high" {
			found = true
			// chain should be HandleUser -> lookup
			if len(p.Via) < 2 {
				t.Errorf("expected chain through a helper, got %d nodes", len(p.Via))
			}
			if !p.TouchPII {
				t.Errorf("expected PII flag (email/users), got false")
			}
		}
	}
	if !found {
		t.Errorf("did not find the high-severity HandleUser->SQL path; paths=%+v", paths)
	}
}

// TestPaths_NoEntrypoint verifies a codebase with no HTTP handler yields no
// source->sink paths (a sink alone is not an attack path without a source).
func TestPaths_NoEntrypoint(t *testing.T) {
	src := `package util

import "os/exec"

func run(cmd string) { _, _ = exec.Command("sh", "-c", cmd).Output() }
`
	dir := t.TempDir()
	f := filepath.Join(dir, "util.go")
	if err := os.WriteFile(f, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	g, err := BuildFromGoFiles([]string{f})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if paths := g.Paths(); len(paths) != 0 {
		t.Errorf("expected no paths without an entrypoint, got %d", len(paths))
	}
}
