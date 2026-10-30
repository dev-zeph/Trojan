package graph

import (
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// keyFixture is a small mixed-language project: a Go handler, an Express
// route with an anonymous callback and two sinks with the same callee, a
// TypeScript route in a subdirectory, and a Python helper.
var keyFixture = map[string]string{
	"main.go": `package main

import (
	"net/http"
	"os/exec"
)

func Handle(w http.ResponseWriter, r *http.Request) {
	run(r.URL.Query().Get("c"))
}

func run(c string) {
	exec.Command("sh", "-c", c).Run()
	exec.Command("echo", c).Run()
}
`,
	"server.js": `const child_process = require("child_process");
const app = require("express")();

app.get("/run", function (req, res) {
  child_process.exec(req.query.cmd);
});

function search(q) {
  db.query("SELECT * FROM t WHERE q = " + q);
  db.query("SELECT 1");
}
`,
	"app/api/orders/route.ts": `export async function POST(req: Request) {
  const body = await req.json();
  eval(body.code);
}
`,
	"worker.py": `import os

def run(cmd):
    os.system(cmd)
`,
}

func writeTree(t *testing.T, dir string, files map[string]string) []string {
	t.Helper()
	var paths []string
	for rel, src := range files {
		p := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(src), 0o600); err != nil {
			t.Fatal(err)
		}
		paths = append(paths, p)
	}
	sort.Strings(paths)
	return paths
}

func keysOf(g *Graph, kinds ...NodeKind) []string {
	want := make(map[NodeKind]bool)
	for _, k := range kinds {
		want[k] = true
	}
	var keys []string
	for _, n := range g.Nodes {
		if len(want) == 0 || want[n.Kind] {
			keys = append(keys, n.Key)
		}
	}
	sort.Strings(keys)
	return keys
}

func TestKeys_IdenticalAcrossBuilds(t *testing.T) {
	dir := t.TempDir()
	files := writeTree(t, dir, keyFixture)

	g1, err := BuildFromFilesRoot(dir, files)
	if err != nil {
		t.Fatal(err)
	}
	// Reverse the file order too: keys must not depend on it.
	rev := append([]string(nil), files...)
	sort.Sort(sort.Reverse(sort.StringSlice(rev)))
	g2, err := BuildFromFilesRoot(dir, rev)
	if err != nil {
		t.Fatal(err)
	}

	k1, k2 := keysOf(g1), keysOf(g2)
	if !reflect.DeepEqual(k1, k2) {
		t.Fatalf("keys differ across builds:\n%v\n%v", k1, k2)
	}

	seen := make(map[string]bool)
	lineish := regexp.MustCompile(`:\d+`)
	for _, k := range k1 {
		if k == "" {
			t.Fatal("node with empty key")
		}
		if seen[k] {
			t.Errorf("duplicate key %q", k)
		}
		seen[k] = true
		if lineish.MatchString(k) || strings.Contains(k, dir) {
			t.Errorf("key %q contains a line number or absolute path", k)
		}
	}

	for _, want := range []string{
		"main.go#main.Handle",
		"main.go#main.run",
		"main.go#main.run@exec.Command#1",
		"main.go#main.run@exec.Command#2",
		"server.js#search",
		"server.js#search@db.query#1",
		"server.js#search@db.query#2",
		"app/api/orders/route.ts#POST",
		"app/api/orders/route.ts#POST@eval#1",
		"worker.py#run",
		"worker.py#run@os.system#1",
	} {
		if !seen[want] {
			t.Errorf("missing key %q; have %v", want, k1)
		}
	}
	t.Logf("keys: %v", k1)

	// BuildFromFiles (root inferred) agrees with the explicit root here,
	// since the temp dir has no project marker above it.
	g3, err := BuildFromFiles(files)
	if err != nil {
		t.Fatal(err)
	}
	if k3 := keysOf(g3); !reflect.DeepEqual(k1, k3) {
		t.Errorf("BuildFromFiles keys differ from BuildFromFilesRoot:\n%v\n%v", k1, k3)
	}
}

func TestKeys_BlankLinesAboveFunctionDoNotMoveKeys(t *testing.T) {
	dir := t.TempDir()
	files := writeTree(t, dir, keyFixture)
	before, err := BuildFromFilesRoot(dir, files)
	if err != nil {
		t.Fatal(err)
	}

	// Insert blank lines above the first function in every file.
	shifted := make(map[string]string)
	for rel, src := range keyFixture {
		switch {
		case strings.HasSuffix(rel, ".go"):
			shifted[rel] = strings.Replace(src, "func Handle", "\n\n\n\nfunc Handle", 1)
		case strings.HasSuffix(rel, ".py"):
			shifted[rel] = strings.Replace(src, "def run", "\n\n\n\ndef run", 1)
		default:
			shifted[rel] = "\n\n\n\n" + src
		}
	}
	writeTree(t, dir, shifted)
	after, err := BuildFromFilesRoot(dir, files)
	if err != nil {
		t.Fatal(err)
	}

	for _, kind := range []NodeKind{KindFunc, KindSink} {
		kb, ka := keysOf(before, kind), keysOf(after, kind)
		if len(kb) == 0 {
			t.Fatalf("fixture produced no %s nodes", kind)
		}
		if !reflect.DeepEqual(kb, ka) {
			t.Errorf("%s keys moved after inserting blank lines:\nbefore %v\nafter  %v", kind, kb, ka)
		}
	}

	// Sanity: lines really did move.
	lineOf := func(g *Graph, key string) int {
		for _, n := range g.Nodes {
			if n.Key == key {
				return n.Line
			}
		}
		return -1
	}
	for _, k := range []string{"main.go#main.Handle", "worker.py#run@os.system#1", "server.js#search"} {
		if lb, la := lineOf(before, k), lineOf(after, k); la != lb+4 {
			t.Errorf("%s: expected line %d -> %d, got %d", k, lb, lb+4, la)
		}
	}
}

func TestKeys_AnonymousAndDuplicateFunctions(t *testing.T) {
	dir := t.TempDir()
	files := writeTree(t, dir, map[string]string{
		"routes.js": `const app = require("express")();
app.get("/a", function (req, res) { eval(req.query.a); });
app.get("/b", function (req, res) { eval(req.query.b); });
class A { get() { return 1; } }
class B { get() { return 2; } }
`,
	})
	g, err := BuildFromFilesRoot(dir, files)
	if err != nil {
		t.Fatal(err)
	}
	keys := keysOf(g, KindFunc)
	seen := make(map[string]bool)
	for _, k := range keys {
		if seen[k] {
			t.Errorf("duplicate func key %q in %v", k, keys)
		}
		seen[k] = true
		if regexp.MustCompile(`:\d+`).MatchString(k) || strings.Contains(k, dir) {
			t.Errorf("anonymous func key leaks line/path: %q", k)
		}
	}
	if len(keys) != 4 {
		t.Errorf("expected 4 func keys (2 callbacks, 2 methods), got %v", keys)
	}
	t.Logf("func keys: %v", keys)
}

// TestAssignKeys_FoldsDatastores covers what Agent B's builders will emit: a
// datastore node per language (or per reference) for the same table. Keys
// make them one node, with both languages' edges and batches.
func TestAssignKeys_FoldsDatastores(t *testing.T) {
	g := New()
	g.Nodes = []Node{
		{Kind: KindFunc, Name: "route.ts.POST", File: "/p/app/route.ts", Line: 1, Batches: []string{BatchJS}},
		{Kind: KindDataStore, Name: "orders", File: "/p/app/route.ts", Line: 3, Batches: []string{BatchJS}},
		{Kind: KindFunc, Name: "main.create", File: "/p/main.py", Line: 1, Batches: []string{BatchPython}},
		{Kind: KindDataStore, Name: "orders", File: "/p/main.py", Line: 2, Batches: []string{BatchPython}},
		{Kind: KindDataStore, Name: "orders", File: "/p/app/route.ts", Line: 4, Batches: []string{BatchJS}},
	}
	for i := range g.Nodes {
		g.Nodes[i].ID = i
	}
	g.Edges = []Edge{
		{Src: 0, Dst: 1, Kind: EdgeWrites},
		{Src: 0, Dst: 4, Kind: EdgeWrites}, // duplicate after fold
		{Src: 2, Dst: 3, Kind: EdgeReads},
	}
	AssignKeys(g, "/p")

	if len(g.Nodes) != 3 {
		t.Fatalf("expected 3 nodes after fold, got %d: %+v", len(g.Nodes), g.Nodes)
	}
	var ds Node
	for i, n := range g.Nodes {
		if n.ID != i {
			t.Errorf("node %d has ID %d", i, n.ID)
		}
		if n.Kind == KindDataStore {
			ds = n
		}
	}
	if ds.Key != "datastore:orders" {
		t.Errorf("datastore key = %q", ds.Key)
	}
	if !reflect.DeepEqual(ds.Batches, []string{BatchJS, BatchPython}) {
		t.Errorf("datastore batches = %v", ds.Batches)
	}
	if len(g.Edges) != 2 {
		t.Fatalf("expected 2 edges after fold, got %+v", g.Edges)
	}
	for _, e := range g.Edges {
		if e.Dst != ds.ID {
			t.Errorf("edge %+v not rewired to datastore %d", e, ds.ID)
		}
	}
	if got := keysOf(g, KindFunc); !reflect.DeepEqual(got, []string{"app/route.ts#POST", "main.py#main.create"}) {
		t.Errorf("func keys: %v", got)
	}

	// FilterBatches(py) keeps the shared datastore and only py's edge.
	py := FilterBatches(g, map[string]bool{BatchPython: true})
	if len(py.Nodes) != 2 || len(py.Edges) != 1 || py.Edges[0].Kind != EdgeReads {
		t.Errorf("FilterBatches(py) = %+v", py)
	}
	for _, n := range py.Nodes {
		if n.Kind == KindDataStore && !reflect.DeepEqual(n.Batches, []string{BatchPython}) {
			t.Errorf("filtered datastore batches = %v", n.Batches)
		}
	}
}
