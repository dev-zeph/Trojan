package ai

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeTemp(t *testing.T, name, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestExtractEnclosingContext_Go(t *testing.T) {
	src := `package main

import "fmt"

func other() {
	fmt.Println("nope")
}

func vulnerable(id string) {
	q := "SELECT * FROM users WHERE id = " + id
	db.Query(q)
}
`
	// Line 10 is the SQL concat inside vulnerable().
	got := ExtractEnclosingContext(writeTemp(t, "main.go", src), 10)
	if !strings.Contains(got, "func vulnerable(id string) {") {
		t.Errorf("expected enclosing func signature, got:\n%s", got)
	}
	if !strings.Contains(got, "db.Query(q)") {
		t.Errorf("expected full function body, got:\n%s", got)
	}
	if strings.Contains(got, "func other()") {
		t.Errorf("should not include the unrelated function, got:\n%s", got)
	}
}

func TestExtractEnclosingContext_JSBraces(t *testing.T) {
	src := `const x = 1;
function handler(req, res) {
  const q = req.query.id;
  res.send(eval(q));
}
const y = 2;
`
	got := ExtractEnclosingContext(writeTemp(t, "app.js", src), 4) // res.send(eval(q))
	if !strings.Contains(got, "function handler(req, res) {") {
		t.Errorf("expected enclosing function signature, got:\n%s", got)
	}
	if !strings.Contains(got, "res.send(eval(q));") {
		t.Errorf("expected body line, got:\n%s", got)
	}
	if strings.Contains(got, "const y = 2;") {
		t.Errorf("should stop at closing brace, got:\n%s", got)
	}
}

func TestExtractEnclosingContext_PythonIndent(t *testing.T) {
	src := `import os

def safe():
    return 1

def vulnerable(request):
    q = request.GET["id"]
    cursor.execute("SELECT * FROM t WHERE id = " + q)
    return q
`
	got := ExtractEnclosingContext(writeTemp(t, "views.py", src), 8) // cursor.execute line
	if !strings.Contains(got, "def vulnerable(request):") {
		t.Errorf("expected enclosing def, got:\n%s", got)
	}
	if !strings.Contains(got, "cursor.execute") {
		t.Errorf("expected body, got:\n%s", got)
	}
	if strings.Contains(got, "def safe():") {
		t.Errorf("should not include unrelated def, got:\n%s", got)
	}
}

func TestExtractEnclosingContext_FallbackOnBrokenGo(t *testing.T) {
	// Unparseable Go -> must fall back to a radius window, not return "".
	src := "package main\nfunc broken( {\n\tdanger()\n"
	got := ExtractEnclosingContext(writeTemp(t, "broken.go", src), 3)
	if !strings.Contains(got, "danger()") {
		t.Errorf("expected radius fallback to include the target line, got:\n%q", got)
	}
}

func TestExtractEnclosingContext_Empty(t *testing.T) {
	if got := ExtractEnclosingContext("", 5); got != "" {
		t.Errorf("empty path should return empty, got %q", got)
	}
	if got := ExtractEnclosingContext(writeTemp(t, "x.go", "package x\n"), 0); got != "" {
		t.Errorf("line 0 should return empty, got %q", got)
	}
}
