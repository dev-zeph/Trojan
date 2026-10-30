package graphstore

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/dev-zeph/trojan/internal/graph"
	"github.com/dev-zeph/trojan/internal/rag"
)

// refreshFixture is a mixed-language project: two Go files, two JS/TS files
// and one Python file, so a JS change has neighbours that must not be parsed.
var refreshFixture = map[string]string{
	"main.go": `package main

import (
	"net/http"
	"os/exec"
)

func Handle(w http.ResponseWriter, r *http.Request) { run(r.URL.Query().Get("c")) }

func run(c string) { exec.Command("sh", "-c", c).Run() }
`,
	"util.go": `package main

func Trim(s string) string { return s }
`,
	"server.js": `const app = require("express")();
app.get("/search", function (req, res) { search(req.query.q); });
function search(q) { db.query("SELECT * FROM t WHERE q = " + q); }
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

func writeProject(t *testing.T, dir string, files map[string]string) {
	t.Helper()
	for rel, src := range files {
		p := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(src), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

// canon reduces a graph to comparable facts: sorted node keys, and sorted
// edges written by key ("src -kind-> dst").
func canon(g *graph.Graph) (keys, edges []string) {
	for _, n := range g.Nodes {
		keys = append(keys, n.Key)
	}
	for _, e := range g.Edges {
		edges = append(edges, fmt.Sprintf("%s -%s-> %s", g.Nodes[e.Src].Key, e.Kind, g.Nodes[e.Dst].Key))
	}
	sort.Strings(keys)
	sort.Strings(edges)
	return keys, edges
}

func TestRefresh_NoChangeReparsesNothing_JSChangeReparsesOnlyJS(t *testing.T) {
	dir := t.TempDir()
	writeProject(t, dir, refreshFixture)

	g1, st, err := Refresh(dir)
	if err != nil {
		t.Fatal(err)
	}
	if st.FilesTotal != 5 || st.FilesReparsed != 5 {
		t.Fatalf("first refresh: want 5/5 parsed, got %+v", st)
	}

	g2, st, err := Refresh(dir)
	if err != nil {
		t.Fatal(err)
	}
	if st.FilesReparsed != 0 {
		t.Fatalf("no-change refresh parsed %d files, want 0 (%+v)", st.FilesReparsed, st)
	}
	k1, e1 := canon(g1)
	k2, e2 := canon(g2)
	if !reflect.DeepEqual(k1, k2) || !reflect.DeepEqual(e1, e2) {
		t.Fatalf("no-change refresh returned a different graph")
	}
	t.Logf("no-change refresh: %+v", st)

	// Modify one JS file: only the JS batch (server.js + route.ts) is parsed.
	writeProject(t, dir, map[string]string{
		"server.js": refreshFixture["server.js"] + "function audit(x) { eval(x); }\n",
	})
	g3, st, err := Refresh(dir)
	if err != nil {
		t.Fatal(err)
	}
	if st.FilesReparsed != 2 {
		t.Fatalf("JS change: want 2 files parsed (the JS batch), got %+v", st)
	}
	t.Logf("JS-change refresh: %+v", st)
	k3, _ := canon(g3)
	if !contains(k3, "server.js#audit@eval#1") {
		t.Errorf("new sink missing after incremental refresh: %v", k3)
	}
	// Go and Python nodes came from the cache, untouched.
	for _, k := range []string{"main.go#main.run@exec.Command#1", "util.go#main.Trim", "worker.py#run@os.system#1"} {
		if !contains(k3, k) {
			t.Errorf("cached node %q lost: %v", k, k3)
		}
	}

	// Removing the only Python file re-parses nothing new but drops py.
	if err := os.Remove(filepath.Join(dir, "worker.py")); err != nil {
		t.Fatal(err)
	}
	g4, st, err := Refresh(dir)
	if err != nil {
		t.Fatal(err)
	}
	if st.FilesReparsed != 0 || st.FilesTotal != 4 {
		t.Fatalf("py removal: want 0 parsed of 4, got %+v", st)
	}
	k4, _ := canon(g4)
	for _, k := range k4 {
		if strings.HasPrefix(k, "worker.py") {
			t.Errorf("removed file still in graph: %q", k)
		}
	}
}

func TestRefresh_IncrementalEqualsFullRebuild(t *testing.T) {
	dir := t.TempDir()
	writeProject(t, dir, refreshFixture)
	if _, _, err := Refresh(dir); err != nil {
		t.Fatal(err)
	}

	// Change JS (new function + call edge) and add a TS file.
	writeProject(t, dir, map[string]string{
		"server.js": `const app = require("express")();
app.get("/search", function (req, res) { search(req.query.q); clean(req.query.q); });
function clean(q) { return q; }
function search(q) { db.query("SELECT * FROM t WHERE q = " + q); db.query("SELECT 1"); }
`,
		"lib/admin.ts": `export function wipe(id: string) { eval(id); }
`,
	})
	inc, st, err := Refresh(dir)
	if err != nil {
		t.Fatal(err)
	}
	if st.FilesReparsed != 3 {
		t.Fatalf("want only the 3 JS-batch files parsed, got %+v", st)
	}

	files, err := rag.WalkSource(dir)
	if err != nil {
		t.Fatal(err)
	}
	full, err := graph.BuildFromFilesRoot(dir, files)
	if err != nil {
		t.Fatal(err)
	}

	ki, ei := canon(inc)
	kf, ef := canon(full)
	if !reflect.DeepEqual(ki, kf) {
		t.Errorf("node keys differ:\nincremental %v\nfull        %v", ki, kf)
	}
	if !reflect.DeepEqual(ei, ef) {
		t.Errorf("edges differ:\nincremental %v\nfull        %v", ei, ef)
	}
	if len(ei) == 0 || !contains(ei, "server.js#GET /search -calls-> server.js#clean") {
		t.Errorf("expected the new call edge, got %v", ei)
	}
	t.Logf("incremental == full: %d nodes, %d edges", len(ki), len(ei))

	// And what was saved reloads to the same thing.
	saved, err := Load(filepath.Join(dir, DefaultDBPath))
	if err != nil {
		t.Fatal(err)
	}
	ks, es := canon(saved)
	if !reflect.DeepEqual(ks, kf) || !reflect.DeepEqual(es, ef) {
		t.Errorf("saved graph differs from full rebuild")
	}
}

// TestRefresh_PlainSaveInvalidatesCache: a graph written by Save (e.g. the
// scan command after an org-context overlay) isn't tied to file hashes, so
// the next Refresh rebuilds fully rather than trusting it.
func TestRefresh_PlainSaveInvalidatesCache(t *testing.T) {
	dir := t.TempDir()
	writeProject(t, dir, refreshFixture)
	if _, _, err := Refresh(dir); err != nil {
		t.Fatal(err)
	}
	if err := Save(filepath.Join(dir, DefaultDBPath), graph.New()); err != nil {
		t.Fatal(err)
	}
	_, st, err := Refresh(dir)
	if err != nil {
		t.Fatal(err)
	}
	if st.FilesReparsed != st.FilesTotal {
		t.Fatalf("want full rebuild after plain Save, got %+v", st)
	}
}

func TestRoundTrip_V2Fields(t *testing.T) {
	g := graph.New()
	g.Nodes = []graph.Node{
		{ID: 0, Kind: graph.KindFunc, Key: "app/api/orders/route.ts#POST", Name: "route.ts.POST",
			File: "app/api/orders/route.ts", Line: 1, Source: true, Guarded: true,
			Tags: map[string]string{"trust_boundary": "public API"}, Batches: []string{graph.BatchJS}},
		{ID: 1, Kind: graph.KindFunc, Key: "components/AdminPanel.tsx#AdminPanel", Name: "AdminPanel.tsx.AdminPanel",
			File: "components/AdminPanel.tsx", Line: 3, ClientSide: true, Batches: []string{graph.BatchJS}},
		{ID: 2, Kind: graph.KindDataStore, Key: "datastore:orders", Name: "orders",
			File: "supabase/migrations/0001_init.sql", Line: 1,
			Tags: map[string]string{"sensitive_data_category": "PCI"}, Batches: []string{graph.BatchJS, graph.BatchPython}},
		{ID: 3, Kind: graph.KindSink, Key: "app/api/orders/route.ts#POST@eval#1", Name: "eval",
			File: "app/api/orders/route.ts", Line: 3, SinkRule: "code injection (eval)", Severity: "high",
			Batches: []string{graph.BatchJS}},
	}
	g.Edges = []graph.Edge{
		{Src: 0, Dst: 2, Kind: graph.EdgeWrites},
		{Src: 1, Dst: 2, Kind: graph.EdgeReads},
		{Src: 0, Dst: 3, Kind: graph.EdgeContains},
	}

	db := filepath.Join(t.TempDir(), DefaultDBPath)
	if err := Save(db, g); err != nil {
		t.Fatal(err)
	}
	got, err := Load(db)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got.Nodes, g.Nodes) {
		t.Errorf("nodes differ:\nwant %+v\ngot  %+v", g.Nodes, got.Nodes)
	}
	if !reflect.DeepEqual(got.Edges, g.Edges) {
		t.Errorf("edges differ:\nwant %+v\ngot  %+v", g.Edges, got.Edges)
	}
}

// v1Schema is graph.db as written before schema v2 (commit a6fe2721).
const v1Schema = `
CREATE TABLE IF NOT EXISTS nodes (
	id        INTEGER PRIMARY KEY,
	kind      TEXT NOT NULL,
	name      TEXT NOT NULL,
	file      TEXT NOT NULL,
	line      INTEGER NOT NULL,
	source    INTEGER NOT NULL,
	pii       INTEGER NOT NULL,
	sink_rule TEXT NOT NULL,
	severity  TEXT NOT NULL,
	tags      TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS edges (
	src  INTEGER NOT NULL,
	dst  INTEGER NOT NULL,
	kind TEXT NOT NULL
);
INSERT INTO nodes VALUES (0, 'func', 'main.Handle', '/p/main.go', 9, 1, 0, '', '', '{"trust_boundary":"public API"}');
INSERT INTO nodes VALUES (1, 'sink', 'exec.Command', '/p/main.go', 11, 0, 0, 'OS command execution', 'high', 'null');
INSERT INTO edges VALUES (0, 1, 'contains');
`

func TestV1DatabaseMigrates(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, DefaultDBPath)
	if err := os.MkdirAll(filepath.Dir(dbPath), 0o755); err != nil {
		t.Fatal(err)
	}
	raw, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(v1Schema); err != nil {
		t.Fatal(err)
	}
	raw.Close()

	// Old rows load, with new fields at their zero values.
	g, err := Load(dbPath)
	if err != nil {
		t.Fatalf("load v1: %v", err)
	}
	if len(g.Nodes) != 2 || len(g.Edges) != 1 {
		t.Fatalf("v1 rows lost: %+v", g)
	}
	if g.Nodes[0].Name != "main.Handle" || !g.Nodes[0].Source || g.Nodes[0].Tags["trust_boundary"] != "public API" {
		t.Errorf("v1 node not preserved: %+v", g.Nodes[0])
	}
	if g.Nodes[0].Key != "" || g.Nodes[0].Guarded || g.Nodes[0].ClientSide {
		t.Errorf("v1 node should have zero v2 fields: %+v", g.Nodes[0])
	}

	raw, err = sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	var version int
	if err := raw.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	var hashTables int
	if err := raw.QueryRow(`SELECT count(*) FROM sqlite_master WHERE type='table' AND name='file_hashes'`).Scan(&hashTables); err != nil {
		t.Fatal(err)
	}
	raw.Close()
	if version != SchemaVersion || hashTables != 1 {
		t.Fatalf("after migration: user_version=%d file_hashes tables=%d", version, hashTables)
	}

	// The migrated file accepts v2 writes, and Refresh over it does a full
	// rebuild (no hashes yet) then goes incremental.
	writeProject(t, dir, refreshFixture)
	_, st, err := Refresh(dir)
	if err != nil {
		t.Fatalf("refresh over migrated db: %v", err)
	}
	if st.FilesReparsed != st.FilesTotal {
		t.Errorf("first refresh over v1 db should be full, got %+v", st)
	}
	if _, st, err = Refresh(dir); err != nil || st.FilesReparsed != 0 {
		t.Errorf("second refresh: %+v %v", st, err)
	}
}

func contains(xs []string, x string) bool {
	for _, y := range xs {
		if y == x {
			return true
		}
	}
	return false
}

func TestRefresh_TSConfigChangeRebuildsJSBatch(t *testing.T) {
	dir := t.TempDir()
	writeProject(t, dir, map[string]string{
		"tsconfig.json":      `{"compilerOptions":{"baseUrl":".","paths":{"@/*":["./*"]}}}`,
		"app/api/x/route.ts": `import { h } from "@/lib/h"; export async function POST() { h(); }`,
		"lib/h.ts":           `export function h() { eval("1"); }`,
		"main.go":            "package main\nfunc main() {}\n",
	})
	if _, _, err := Refresh(dir); err != nil {
		t.Fatal(err)
	}
	if _, st, err := Refresh(dir); err != nil || st.FilesReparsed != 0 {
		t.Fatalf("no-change refresh: %+v, %v", st, err)
	}
	writeProject(t, dir, map[string]string{
		"tsconfig.json": `{"compilerOptions":{"baseUrl":".","paths":{"~/*":["./*"]}}}`,
	})
	_, st, err := Refresh(dir)
	if err != nil {
		t.Fatal(err)
	}
	if st.FilesReparsed != 2 {
		t.Fatalf("tsconfig edit should re-parse the 2 TS files (not Go), got %+v", st)
	}
}

// A graph cached by an older builder (different graph.BuilderVersion) is
// rebuilt in full, so new sinks and rules reach projects whose files did not
// change.
func TestRefresh_BuilderVersionChangeRebuilds(t *testing.T) {
	dir := t.TempDir()
	writeProject(t, dir, refreshFixture)
	if _, _, err := Refresh(dir); err != nil {
		t.Fatal(err)
	}
	db, err := open(filepath.Join(dir, DefaultDBPath))
	if err != nil {
		t.Fatal(err)
	}
	if got := readBuilder(db); got != graph.BuilderVersion {
		t.Fatalf("builder version recorded as %q, want %q", got, graph.BuilderVersion)
	}
	if _, err := db.Exec(`UPDATE meta SET value = 'old' WHERE key = ?`, metaBuilderKey); err != nil {
		t.Fatal(err)
	}
	db.Close()
	_, st, err := Refresh(dir)
	if err != nil {
		t.Fatal(err)
	}
	if st.FilesReparsed != st.FilesTotal {
		t.Fatalf("want full rebuild after a builder change, got %+v", st)
	}
	if _, st, err := Refresh(dir); err != nil || st.FilesReparsed != 0 {
		t.Fatalf("second refresh should hit the cache: %+v, %v", st, err)
	}
}
