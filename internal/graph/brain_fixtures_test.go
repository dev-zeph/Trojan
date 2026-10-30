package graph

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// These tests are the acceptance check for the security-brain graph work:
// every FLAG in internal/testdata/ANSWERS.md is detected, every SAFE item is
// not reported as an unguarded path, cross-file resolution works, and the
// .env canary never reaches the graph.

func fixtureGraph(t *testing.T, app string) *Graph {
	t.Helper()
	root := filepath.Join("..", "testdata", app)
	var files []string
	err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && d.Name() == "node_modules" {
			return filepath.SkipDir
		}
		if !d.IsDir() {
			files = append(files, p)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	g, err := BuildFromFiles(files)
	if err != nil {
		t.Fatalf("build %s: %v", app, err)
	}
	return g
}

// funcNode finds the func node with this Name in a file ending in fileSuffix.
func funcNode(t *testing.T, g *Graph, fileSuffix, name string) Node {
	t.Helper()
	for _, n := range g.Nodes {
		if n.Kind == KindFunc && n.Name == name && strings.HasSuffix(filepath.ToSlash(n.File), fileSuffix) {
			return n
		}
	}
	var names []string
	for _, n := range g.Nodes {
		if n.Kind == KindFunc {
			names = append(names, n.File+":"+n.Name)
		}
	}
	t.Fatalf("no func %q in %s; have %v", name, fileSuffix, names)
	return Node{}
}

// unguardedFrom returns the UnguardedPaths starting at the given source.
func unguardedFrom(g *Graph, src Node) []AttackPath {
	var out []AttackPath
	for _, p := range g.UnguardedPaths() {
		if p.Source.ID == src.ID {
			out = append(out, p)
		}
	}
	return out
}

func hasStoreAccess(paths []AttackPath, store string, kind EdgeKind) bool {
	for _, p := range paths {
		if p.Sink.Kind == KindDataStore && p.Sink.Name == store && p.Access == kind {
			return true
		}
	}
	return false
}

func hasHighSQL(paths []AttackPath) bool {
	for _, p := range paths {
		if p.Sink.Kind == KindSink && p.Severity == "high" && strings.Contains(p.Sink.SinkRule, "SQL") {
			return true
		}
	}
	return false
}

func hasEdge(g *Graph, src, dst int, kind EdgeKind) bool {
	for _, e := range g.Edges {
		if e.Src == src && e.Dst == dst && e.Kind == kind {
			return true
		}
	}
	return false
}

func storeNode(t *testing.T, g *Graph, name string) Node {
	t.Helper()
	for _, n := range g.Nodes {
		if n.Kind == KindDataStore && n.Name == name {
			return n
		}
	}
	t.Fatalf("no datastore node %q", name)
	return Node{}
}

// --- vibeapp (Next.js + Supabase) ---

func TestVibeapp1_OrdersPOSTUnguardedWrite(t *testing.T) {
	g := fixtureGraph(t, "vibeapp")
	post := funcNode(t, g, "app/api/orders/route.ts", "route.ts.POST")
	if !post.Source || post.Guarded {
		t.Fatalf("orders POST: want Source && !Guarded, got %+v", post)
	}
	if !hasStoreAccess(unguardedFrom(g, post), "orders", EdgeWrites) {
		t.Errorf("orders POST: expected unguarded write to datastore orders")
	}
}

func TestVibeapp1_CrossFileHelper(t *testing.T) {
	g := fixtureGraph(t, "vibeapp")
	post := funcNode(t, g, "app/api/orders/route.ts", "route.ts.POST")
	helper := funcNode(t, g, "lib/supabase/server.ts", "server.ts.createClient")
	if !hasEdge(g, post.ID, helper.ID, EdgeCalls) {
		t.Errorf("expected orders POST -calls-> lib/supabase/server.ts createClient (via @/ alias)")
	}
	orders := storeNode(t, g, "orders")
	if !hasEdge(g, post.ID, orders.ID, EdgeWrites) {
		t.Errorf("expected orders POST -writes-> datastore orders")
	}
}

func TestVibeapp2_ProfileGETIsSafe(t *testing.T) {
	g := fixtureGraph(t, "vibeapp")
	get := funcNode(t, g, "app/api/profile/route.ts", "route.ts.GET")
	if !get.Source {
		t.Fatalf("profile GET should be an entrypoint")
	}
	if !get.Guarded {
		t.Errorf("profile GET checks supabase.auth.getUser(); want Guarded")
	}
	if p := unguardedFrom(g, get); len(p) != 0 {
		t.Errorf("profile GET must not be reported unguarded, got %d paths", len(p))
	}
	profiles := storeNode(t, g, "profiles")
	if !hasEdge(g, get.ID, profiles.ID, EdgeReads) {
		t.Errorf("expected profile GET -reads-> profiles")
	}
}

func TestVibeapp3_ClientComponentReachesServiceRole(t *testing.T) {
	g := fixtureGraph(t, "vibeapp")
	wipe := funcNode(t, g, "components/AdminPanel.tsx", "AdminPanel.tsx.wipe")
	if !wipe.ClientSide {
		t.Fatalf("wipe lives in a \"use client\" file; want ClientSide")
	}
	if !hasEdge(g, wipe.ID, storeNode(t, g, "profiles").ID, EdgeWrites) {
		t.Errorf("expected wipe -writes-> profiles")
	}
	var found bool
	for _, e := range g.ClientExposures() {
		if e.Client.ID == wipe.ID && e.Reached.SinkRule == ruleServiceRole &&
			strings.HasSuffix(filepath.ToSlash(e.Reached.File), "lib/supabase/admin.ts") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected ClientExposures to flag wipe reaching the service-role client in lib/supabase/admin.ts; got %+v", g.ClientExposures())
	}
}

func TestVibeapp4_ServerActionUnguardedDelete(t *testing.T) {
	g := fixtureGraph(t, "vibeapp")
	del := funcNode(t, g, "app/actions.ts", "actions.ts.deletePost")
	if !del.Source || del.Guarded {
		t.Fatalf("deletePost: want Source (server action) && !Guarded, got %+v", del)
	}
	if !hasStoreAccess(unguardedFrom(g, del), "posts", EdgeWrites) {
		t.Errorf("deletePost: expected unguarded write to posts")
	}
}

func TestVibeapp5_ExportRawSQL(t *testing.T) {
	g := fixtureGraph(t, "vibeapp")
	get := funcNode(t, g, "app/api/export/route.ts", "route.ts.GET")
	if !hasHighSQL(unguardedFrom(g, get)) {
		t.Errorf("export GET: expected unguarded high-severity SQL concat sink")
	}
}

func TestVibeapp_MiddlewareMatcherDoesNotGuardAPI(t *testing.T) {
	g := fixtureGraph(t, "vibeapp")
	mw := funcNode(t, g, "middleware.ts", "middleware.ts.middleware")
	if !mw.Source {
		t.Errorf("middleware should be an entrypoint")
	}
	for _, f := range []string{"app/api/orders/route.ts", "app/api/export/route.ts"} {
		for _, n := range g.Nodes {
			if n.Source && strings.HasSuffix(filepath.ToSlash(n.File), f) && n.Guarded {
				t.Errorf("%s %s guarded, but the matcher only covers /dashboard", f, n.Name)
			}
		}
	}
}

// writeTree writes files (relative path -> content) under a temp dir and
// returns the absolute file list.
func writeTree(t *testing.T, tree map[string]string) []string {
	t.Helper()
	dir := t.TempDir()
	var files []string
	for rel, content := range tree {
		p := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		if !strings.HasSuffix(rel, ".json") {
			files = append(files, p)
		}
	}
	return files
}

// TestNextMiddlewareCoverage: auth middleware guards exactly the routes its
// matcher covers, and every route when there is no matcher.
func TestNextMiddlewareCoverage(t *testing.T) {
	route := `export async function POST() { await supabase.from("orders").insert({}); }`
	for _, tc := range []struct {
		matcher string
		guarded bool
	}{
		{`export const config = { matcher: ["/dashboard/:path*"] };`, false},
		{`export const config = { matcher: ["/api/:path*"] };`, true},
		{``, true},
	} {
		files := writeTree(t, map[string]string{
			"package.json":            `{}`,
			"app/api/orders/route.ts": route,
			"middleware.ts": `import { NextResponse } from "next/server";
export async function middleware(req) {
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) return NextResponse.redirect("/login");
}
` + tc.matcher,
		})
		g, err := BuildFromFiles(files)
		if err != nil {
			t.Fatal(err)
		}
		post := funcNode(t, g, "app/api/orders/route.ts", "route.ts.POST")
		if post.Guarded != tc.guarded {
			t.Errorf("matcher %q: POST guarded=%v, want %v", tc.matcher, post.Guarded, tc.guarded)
		}
	}
}

// TestNextMiddlewareSessionRefreshIsNotAGuard: Supabase's best-effort
// session refresh (getUser() with no redirect/401) gates nothing, so routes
// it covers stay unguarded. Found on a real project (trojan-web proxy.ts).
func TestNextMiddlewareSessionRefreshIsNotAGuard(t *testing.T) {
	files := writeTree(t, map[string]string{
		"package.json":            `{}`,
		"app/api/orders/route.ts": `export async function POST() { await supabase.from("orders").insert({}); }`,
		"proxy.ts": `export async function proxy(request) {
  try { await supabase.auth.getUser(); } catch {}
  return NextResponse.next({ request });
}`,
	})
	g, err := BuildFromFiles(files)
	if err != nil {
		t.Fatal(err)
	}
	if post := funcNode(t, g, "app/api/orders/route.ts", "route.ts.POST"); post.Guarded {
		t.Errorf("session-refresh proxy must not guard POST")
	}
	if mw := funcNode(t, g, "proxy.ts", "proxy.ts.proxy"); !mw.Source {
		t.Errorf("proxy.ts (Next 16 middleware) should be an entrypoint")
	}
}

// TestTSXRecovery: ts.wasm has no TSX grammar, so JSX plus typed params can
// turn a whole page into ERROR nodes; queries inside must still be found and
// owned by the page function.
func TestTSXRecovery(t *testing.T) {
	files := writeTree(t, map[string]string{
		"app/dashboard/page.tsx": `import { createClient } from "@/lib/supabase/server";
export default async function DashboardPage({ searchParams }: { searchParams: Promise<{ a?: string }> }) {
  const supabase = await createClient();
  const { data } = await supabase.from("users").select("id");
  return (<>
    <i className="corner" />
    <div style={{minHeight: "1px"}}>{data}</div>
  </>);
}
`,
	})
	g, err := BuildFromFiles(files)
	if err != nil {
		t.Fatal(err)
	}
	page := funcNode(t, g, "app/dashboard/page.tsx", "page.tsx.DashboardPage")
	if !hasEdge(g, page.ID, storeNode(t, g, "users").ID, EdgeReads) {
		t.Errorf("expected DashboardPage -reads-> users despite the TSX misparse")
	}
}

func TestSQLTables(t *testing.T) {
	for _, tc := range []struct {
		sql  string
		want map[string]EdgeKind
	}{
		{`"SELECT * FROM invoices WHERE customer = '" + c + "'"`, map[string]EdgeKind{"invoices": EdgeReads}},
		{"`INSERT INTO bookings (a) VALUES (?)`", map[string]EdgeKind{"bookings": EdgeWrites}},
		{`"UPDATE public.orders SET total = 1"`, map[string]EdgeKind{"orders": EdgeWrites}},
		{`"DELETE FROM notes WHERE id IN (SELECT id FROM users)"`, map[string]EdgeKind{"notes": EdgeWrites, "users": EdgeReads}},
		{`"SELECT a FROM x JOIN y ON x.id = y.id ORDER BY updated_at"`, map[string]EdgeKind{"x": EdgeReads, "y": EdgeReads}},
		{`"not sql at all"`, map[string]EdgeKind{}},
	} {
		got := map[string]EdgeKind{}
		for _, a := range sqlTables(tc.sql) {
			got[a.store] = a.kind
		}
		if len(got) != len(tc.want) {
			t.Errorf("%s: got %v want %v", tc.sql, got, tc.want)
			continue
		}
		for k, v := range tc.want {
			if got[k] != v {
				t.Errorf("%s: %s got %q want %q", tc.sql, k, got[k], v)
			}
		}
	}
}

func TestVibeapp5_RawSQLReadsInvoices(t *testing.T) {
	g := fixtureGraph(t, "vibeapp")
	get := funcNode(t, g, "app/api/export/route.ts", "route.ts.GET")
	if !hasStoreAccess(unguardedFrom(g, get), "invoices", EdgeReads) {
		t.Errorf("export GET: expected unguarded read of invoices from the raw SQL text")
	}
}

// --- expressapp ---

func TestExpressE1_RequireAuthIsSafe(t *testing.T) {
	g := fixtureGraph(t, "expressapp")
	h := funcNode(t, g, "expressapp/server.js", "server.js.POST /api/notes")
	if !h.Source || !h.Guarded {
		t.Fatalf("POST /api/notes: want Source && Guarded (requireAuth), got %+v", h)
	}
	if p := unguardedFrom(g, h); len(p) != 0 {
		t.Errorf("POST /api/notes must not be reported unguarded, got %d", len(p))
	}
	if !hasEdge(g, h.ID, storeNode(t, g, "notes").ID, EdgeWrites) {
		t.Errorf("expected POST /api/notes -writes-> notes")
	}
}

func TestExpressE2_UnguardedDelete(t *testing.T) {
	g := fixtureGraph(t, "expressapp")
	h := funcNode(t, g, "expressapp/server.js", "server.js.DELETE /api/notes/:id")
	if !hasStoreAccess(unguardedFrom(g, h), "notes", EdgeWrites) {
		t.Errorf("DELETE /api/notes/:id: expected unguarded write to notes")
	}
}

func TestExpressE3_SearchRawSQL(t *testing.T) {
	g := fixtureGraph(t, "expressapp")
	h := funcNode(t, g, "expressapp/server.js", "server.js.GET /api/search")
	if !hasHighSQL(unguardedFrom(g, h)) {
		t.Errorf("GET /api/search: expected unguarded high-severity SQL concat sink")
	}
}

func TestExpressE4_MountedRouterUnguardedRead(t *testing.T) {
	g := fixtureGraph(t, "expressapp")
	// The router in routes/users.js registers "/:id"; its name carries the
	// mount prefix from server.js, proving the cross-file mount resolved.
	h := funcNode(t, g, "routes/users.js", "users.js.GET /api/users/:id")
	if !h.Source || h.Guarded {
		t.Fatalf("users GET: want Source && !Guarded, got %+v", h)
	}
	if !hasStoreAccess(unguardedFrom(g, h), "users", EdgeReads) {
		t.Errorf("users GET: expected unguarded read of users")
	}
}

func TestExpressHealthTouchesNothing(t *testing.T) {
	g := fixtureGraph(t, "expressapp")
	h := funcNode(t, g, "expressapp/server.js", "server.js.GET /health")
	if p := unguardedFrom(g, h); len(p) != 0 {
		t.Errorf("/health should reach nothing, got %+v", p)
	}
}

func TestExpressServiceRoleOnServerOnly(t *testing.T) {
	g := fixtureGraph(t, "expressapp")
	var sr bool
	for _, n := range g.Nodes {
		if n.Kind == KindSink && n.SinkRule == ruleServiceRole && strings.HasSuffix(filepath.ToSlash(n.File), "lib/db.js") {
			sr = true
		}
	}
	if !sr {
		t.Errorf("expected a service-role client sink in lib/db.js")
	}
	if e := g.ClientExposures(); len(e) != 0 {
		t.Errorf("server-only app should have no client exposures, got %+v", e)
	}
}

// TestExpressRouterAuthMounts covers guards applied at mount time and via a
// preceding app.use(requireAuth).
func TestExpressRouterAuthMounts(t *testing.T) {
	files := writeTree(t, map[string]string{
		"server.js": `const express = require("express");
const { requireAuth } = require("./auth");
const admin = require("./admin");
const open = require("./open");
const app = express();
app.use("/open", open);
app.use("/admin", requireAuth, admin);
`,
		"auth.js": `function requireAuth(req, res, next) { next(); }
module.exports = { requireAuth };`,
		"admin.js": `const router = require("express").Router();
router.post("/wipe", async (req, res) => { await supabase.from("t").delete(); });
module.exports = router;`,
		"open.js": `const express = require("express");
const router = express.Router();
router.post("/x", async (req, res) => { await supabase.from("t").delete(); });
module.exports = router;`,
	})
	g, err := BuildFromFiles(files)
	if err != nil {
		t.Fatal(err)
	}
	if n := funcNode(t, g, "admin.js", "admin.js.POST /admin/wipe"); !n.Guarded {
		t.Errorf("/admin/wipe mounted behind requireAuth; want Guarded")
	}
	if n := funcNode(t, g, "open.js", "open.js.POST /open/x"); n.Guarded {
		t.Errorf("/open/x has no auth; want !Guarded")
	}
}

func TestDestructuredRequireExec(t *testing.T) {
	files := writeTree(t, map[string]string{
		"api.js": `const { exec } = require("child_process");
const app = require("express")();
app.get("/run", (req, res) => { exec(req.query.cmd); });`,
	})
	g, err := BuildFromFiles(files)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, p := range g.UnguardedPaths() {
		if p.Sink.SinkRule == "OS command execution" {
			found = true
		}
	}
	if !found {
		t.Errorf("destructured exec from child_process not detected as a sink")
	}
}

// --- pyapp ---

func TestPyP1_CreateItemUnguardedWrite(t *testing.T) {
	g := fixtureGraph(t, "pyapp")
	fn := funcNode(t, g, "pyapp/main.py", "main.py.create_item")
	if !fn.Source || fn.Guarded {
		t.Fatalf("create_item: want Source && !Guarded, got %+v", fn)
	}
	if !hasStoreAccess(unguardedFrom(g, fn), "items", EdgeWrites) {
		t.Errorf("create_item: expected unguarded write to items")
	}
}

func TestPyP2_MeIsSafe(t *testing.T) {
	g := fixtureGraph(t, "pyapp")
	fn := funcNode(t, g, "pyapp/main.py", "main.py.me")
	if !fn.Guarded {
		t.Errorf("me uses Depends(get_current_user); want Guarded")
	}
	if p := unguardedFrom(g, fn); len(p) != 0 {
		t.Errorf("me must not be reported unguarded, got %d", len(p))
	}
	if !hasEdge(g, fn.ID, storeNode(t, g, "profiles").ID, EdgeReads) {
		t.Errorf("expected me -reads-> profiles")
	}
}

func TestPyP3_SearchRawSQLCrossFile(t *testing.T) {
	g := fixtureGraph(t, "pyapp")
	fn := funcNode(t, g, "pyapp/main.py", "main.py.search")
	if !hasHighSQL(unguardedFrom(g, fn)) {
		t.Errorf("search: expected unguarded high-severity SQL (f-string) sink")
	}
	conn := funcNode(t, g, "pyapp/db.py", "db.py.get_conn")
	if !hasEdge(g, fn.ID, conn.ID, EdgeCalls) {
		t.Errorf("expected main.py search -calls-> db.py get_conn")
	}
}

func TestPyP4_FlaskAdminDeleteUnguarded(t *testing.T) {
	g := fixtureGraph(t, "pyapp")
	fn := funcNode(t, g, "pyapp/flask_app.py", "flask_app.py.admin_delete")
	if !fn.Source || fn.Guarded {
		t.Fatalf("admin_delete: want Source && !Guarded, got %+v", fn)
	}
	if !hasStoreAccess(unguardedFrom(g, fn), "items", EdgeWrites) {
		t.Errorf("admin_delete: expected unguarded write to items")
	}
}

func TestPyP5_LoginRequiredIsSafe(t *testing.T) {
	g := fixtureGraph(t, "pyapp")
	fn := funcNode(t, g, "pyapp/flask_app.py", "flask_app.py.account")
	if !fn.Source || !fn.Guarded {
		t.Fatalf("account: want Source && Guarded (@login_required), got %+v", fn)
	}
	if p := unguardedFrom(g, fn); len(p) != 0 {
		t.Errorf("account must not be reported unguarded, got %d", len(p))
	}
}

func TestPySupabaseExecuteIsNotSQL(t *testing.T) {
	g := fixtureGraph(t, "pyapp")
	for _, n := range g.Nodes {
		if n.Kind == KindSink && strings.Contains(n.SinkRule, "SQL") && strings.Contains(n.Name, "table") {
			t.Errorf("supabase .execute() misread as SQL sink: %+v", n)
		}
	}
}

// --- all fixtures ---

func TestCanaryNeverInGraph(t *testing.T) {
	const canary = "TROJAN_CANARY_DO_NOT_LEAK_7731"
	for _, app := range []string{"vibeapp", "expressapp", "pyapp"} {
		g := fixtureGraph(t, app)
		raw, err := json.Marshal(g)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(raw), canary) {
			t.Errorf("%s: canary value leaked into the graph", app)
		}
	}
}

func TestNoLineNumbersInNames(t *testing.T) {
	for _, app := range []string{"vibeapp", "expressapp", "pyapp"} {
		g := fixtureGraph(t, app)
		for _, n := range g.Nodes {
			if strings.Contains(n.Name, ".go:") || strings.Contains(n.Name, ".ts:") || strings.Contains(n.Name, ".js:") || strings.Contains(n.Name, "\\n") {
				t.Errorf("%s: node name carries a position: %q", app, n.Name)
			}
		}
	}
}
