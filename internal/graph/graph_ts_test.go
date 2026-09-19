package graph

import (
	"os"
	"path/filepath"
	"testing"
)

// TestPaths_FindsSourceToSink_JS mirrors TestPaths_FindsSourceToSink in
// graph_test.go, but for the tree-sitter-WASM path: an Express-style route
// handler (source) reaches a SQL sink through a helper function, extracted
// from JavaScript via internal/graph/tswasm instead of go/ast.
func TestPaths_FindsSourceToSink_JS(t *testing.T) {
	src := `const express = require("express");
const app = express();
const db = require("./db");

app.get("/user", function (req, res) {
  const id = req.query.id;
  lookup(id);
});

// lookup builds a query by concatenation, the classic injection.
function lookup(id) {
  const email = "x";
  db.query("SELECT * FROM users WHERE id = " + id);
  return email;
}
`
	dir := t.TempDir()
	f := filepath.Join(dir, "api.js")
	if err := os.WriteFile(f, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}

	g, err := BuildFromFiles([]string{f})
	if err != nil {
		t.Fatalf("build: %v", err)
	}

	paths := g.Paths()
	if len(paths) == 0 {
		t.Fatal("expected at least one source->sink path, got none")
	}

	var found bool
	for _, p := range paths {
		if p.Severity == "high" {
			found = true
			if len(p.Via) < 2 {
				t.Errorf("expected chain through a helper, got %d nodes", len(p.Via))
			}
			if !p.Source.Source {
				t.Errorf("expected source node to be flagged Source")
			}
			if !p.TouchPII {
				t.Errorf("expected PII flag (email), got false")
			}
		}
	}
	if !found {
		t.Errorf("did not find the high-severity route-handler->SQL path; paths=%+v", paths)
	}
}

// TestPaths_NoEntrypoint_JS verifies a JS file with a dangerous sink but no
// route handler yields no source->sink paths.
func TestPaths_NoEntrypoint_JS(t *testing.T) {
	src := `function run(cmd) {
  const cp = require("child_process");
  cp.exec(cmd);
}
`
	dir := t.TempDir()
	f := filepath.Join(dir, "util.js")
	if err := os.WriteFile(f, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	g, err := BuildFromFiles([]string{f})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if paths := g.Paths(); len(paths) != 0 {
		t.Errorf("expected no paths without a route handler, got %d", len(paths))
	}
}

// TestPaths_FindsSourceToSink_Python is the Python counterpart: a Flask route
// (source, via the @app.route decorator) reaches a SQL sink through a helper.
func TestPaths_FindsSourceToSink_Python(t *testing.T) {
	src := `from flask import Flask, request
import sqlite3

app = Flask(__name__)
db = sqlite3.connect("app.db")


@app.route("/user")
def handle_user():
    user_id = request.args.get("id")
    lookup(user_id)


def lookup(user_id):
    email = "x"
    cursor = db.cursor()
    cursor.execute("SELECT * FROM users WHERE id = " + user_id)
    return email
`
	dir := t.TempDir()
	f := filepath.Join(dir, "api.py")
	if err := os.WriteFile(f, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}

	g, err := BuildFromFiles([]string{f})
	if err != nil {
		t.Fatalf("build: %v", err)
	}

	paths := g.Paths()
	if len(paths) == 0 {
		t.Fatal("expected at least one source->sink path, got none")
	}

	var found bool
	for _, p := range paths {
		if p.Severity == "high" {
			found = true
			if len(p.Via) < 2 {
				t.Errorf("expected chain through a helper, got %d nodes", len(p.Via))
			}
			if !p.Source.Source {
				t.Errorf("expected source node to be flagged Source")
			}
			if !p.TouchPII {
				t.Errorf("expected PII flag (email), got false")
			}
		}
	}
	if !found {
		t.Errorf("did not find the high-severity handle_user->SQL path; paths=%+v", paths)
	}
}

// TestPaths_NoEntrypoint_Python verifies a Python file with a dangerous sink
// but no Flask/Django/FastAPI route reaches it yields no paths.
func TestPaths_NoEntrypoint_Python(t *testing.T) {
	src := `import os


def run(cmd):
    os.system(cmd)
`
	dir := t.TempDir()
	f := filepath.Join(dir, "util.py")
	if err := os.WriteFile(f, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	g, err := BuildFromFiles([]string{f})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if paths := g.Paths(); len(paths) != 0 {
		t.Errorf("expected no paths without a route handler, got %d", len(paths))
	}
}

// TestPaths_FindsSourceToSink_TypeScript proves the TypeScript grammar path
// (same extraction code as JavaScript, different tree-sitter grammar) finds
// the same shape of source->sink path when the handler has type annotations.
func TestPaths_FindsSourceToSink_TypeScript(t *testing.T) {
	src := `import express, { Request, Response } from "express";
const app = express();
const db = require("./db");

app.get("/user", function (req: Request, res: Response): void {
  const id: string = req.query.id as string;
  lookup(id);
});

function lookup(id: string): void {
  const email: string = "x";
  db.query("SELECT * FROM users WHERE id = " + id);
}
`
	dir := t.TempDir()
	f := filepath.Join(dir, "api.ts")
	if err := os.WriteFile(f, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}

	g, err := BuildFromFiles([]string{f})
	if err != nil {
		t.Fatalf("build: %v", err)
	}

	paths := g.Paths()
	if len(paths) == 0 {
		t.Fatal("expected at least one source->sink path in the TypeScript sample, got none")
	}
	var found bool
	for _, p := range paths {
		if p.Severity == "high" {
			found = true
		}
	}
	if !found {
		t.Errorf("did not find the high-severity path; paths=%+v", paths)
	}
}

// TestBuildFromFiles_MixedLanguages proves the dispatch layer: a Go file and
// a JS file in the same BuildFromFiles call each contribute their own
// source->sink path to one combined graph.
func TestBuildFromFiles_MixedLanguages(t *testing.T) {
	dir := t.TempDir()

	goSrc := `package api

import (
	"net/http"
	"os/exec"
)

func HandleRun(w http.ResponseWriter, r *http.Request) {
	cmd := r.URL.Query().Get("cmd")
	run(cmd)
}

func run(cmd string) {
	_, _ = exec.Command("sh", "-c", cmd).Output()
}
`
	jsSrc := `const app = require("express")();

app.get("/user", function (req, res) {
  lookup(req.query.id);
});

function lookup(id) {
  const db = require("./db");
  db.query("SELECT * FROM users WHERE id = " + id);
}
`
	goFile := filepath.Join(dir, "api.go")
	jsFile := filepath.Join(dir, "api.js")
	if err := os.WriteFile(goFile, []byte(goSrc), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(jsFile, []byte(jsSrc), 0o600); err != nil {
		t.Fatal(err)
	}

	g, err := BuildFromFiles([]string{goFile, jsFile})
	if err != nil {
		t.Fatalf("build: %v", err)
	}

	paths := g.Paths()
	if len(paths) < 2 {
		t.Fatalf("expected at least 2 paths (one Go, one JS), got %d: %+v", len(paths), paths)
	}

	var sawGo, sawJS bool
	for _, p := range paths {
		if p.Sink.SinkRule == "OS command execution" {
			sawGo = true
		}
		if p.Severity == "high" && p.Sink.SinkRule != "OS command execution" {
			sawJS = true
		}
	}
	if !sawGo {
		t.Error("expected the Go source->sink path to survive the merge")
	}
	if !sawJS {
		t.Error("expected the JS source->sink path to survive the merge")
	}
}
