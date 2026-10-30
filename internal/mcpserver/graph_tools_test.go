package mcpserver

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"

	"github.com/dev-zeph/trojan/internal/memory"
	"github.com/dev-zeph/trojan/internal/normalizer"
	"github.com/dev-zeph/trojan/internal/orgcontext"
	"github.com/dev-zeph/trojan/internal/rag"
	"github.com/dev-zeph/trojan/internal/reach"
)

// brainFixture copies internal/testdata/<app> into a temp project (so the
// graph and memory databases never land in the repo) under a signed-in HOME.
func brainFixture(t *testing.T, app string) (projectFunc, string) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	os.MkdirAll(filepath.Join(home, ".trojan"), 0700)                                                                   //nolint:errcheck
	os.WriteFile(filepath.Join(home, ".trojan", "config.json"), []byte(`{"access_token":"tok","familiarity":0}`), 0600) //nolint:errcheck
	src := filepath.Join("..", "testdata", app)
	dst := filepath.Join(home, app)
	err := filepath.WalkDir(src, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		if d.IsDir() {
			if d.Name() == ".trojan" {
				return filepath.SkipDir
			}
			return os.MkdirAll(filepath.Join(dst, rel), 0o755)
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(dst, rel), data, 0o644)
	})
	if err != nil {
		t.Fatal(err)
	}
	return func(context.Context, mcp.CallToolRequest) (string, error) { return dst, nil }, dst
}

func mustCall(t *testing.T, h func(context.Context, mcp.CallToolRequest) (*mcp.CallToolResult, error), args map[string]any) string {
	t.Helper()
	text, isErr := callTool(t, h, args)
	if isErr {
		t.Fatalf("tool error: %s", text)
	}
	return text
}

type attackPathsOut struct {
	Paths []struct {
		Route, Entry, Reaches, At, Severity string
	} `json:"unprotected_paths"`
	Exposures []struct {
		Client  string `json:"browser_code"`
		Reaches string
		At      string
	} `json:"browser_exposures"`
}

func attackPaths(t *testing.T, app string) attackPathsOut {
	project, _ := brainFixture(t, app)
	var out attackPathsOut
	if err := json.Unmarshal([]byte(mustCall(t, handleAttackPaths(project), nil)), &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func hasPath(out attackPathsOut, route, reachesSub string) bool {
	for _, p := range out.Paths {
		if p.Route == route && strings.Contains(p.Reaches, reachesSub) {
			return true
		}
	}
	return false
}

func hasRoute(out attackPathsOut, route string) bool {
	return hasPath(out, route, "")
}

// TestAttackPathsMatchAnswerKey checks get_attack_paths against
// internal/testdata/ANSWERS.md: every FLAG reported, no SAFE item.
func TestAttackPathsMatchAnswerKey(t *testing.T) {
	t.Run("vibeapp", func(t *testing.T) {
		out := attackPaths(t, "vibeapp")
		if !hasPath(out, "POST /api/orders", "writes orders") {
			t.Error("item 1: POST /api/orders writing orders missing")
		}
		var admin bool
		for _, e := range out.Exposures {
			if strings.Contains(e.Client, "components/AdminPanel.tsx") && strings.HasPrefix(e.At, "lib/supabase/admin.ts:") {
				admin = true
			}
		}
		if !admin {
			t.Errorf("item 3: AdminPanel reaching the service-role client missing: %+v", out.Exposures)
		}
		if !hasPath(out, "server action deletePost", "writes posts") {
			t.Error("item 4: deletePost writing posts missing")
		}
		if !hasPath(out, "GET /api/export", "SQL") {
			t.Error("item 5: export raw SQL missing")
		}
		if hasRoute(out, "GET /api/profile") {
			t.Error("item 2 (SAFE): GET /api/profile reported")
		}
		for _, p := range out.Paths {
			if !strings.Contains(p.Entry, ":") || !strings.Contains(p.At, ":") {
				t.Errorf("path without file:line: %+v", p)
			}
		}
		if out.Paths[0].Severity != "high" {
			t.Errorf("not ranked: first path %+v", out.Paths[0])
		}
	})
	t.Run("expressapp", func(t *testing.T) {
		out := attackPaths(t, "expressapp")
		if !hasPath(out, "DELETE /api/notes/:id", "writes notes") {
			t.Error("E2 missing")
		}
		if !hasPath(out, "GET /api/search", "SQL") {
			t.Error("E3 missing")
		}
		if !hasPath(out, "GET /api/users/:id", "reads users") {
			t.Error("E4 missing")
		}
		if hasRoute(out, "POST /api/notes") {
			t.Error("E1 (SAFE) reported")
		}
	})
	t.Run("pyapp", func(t *testing.T) {
		out := attackPaths(t, "pyapp")
		if !hasPath(out, "POST /items", "writes items") {
			t.Error("P1 missing")
		}
		if !hasPath(out, "GET /search", "SQL") {
			t.Error("P3 missing")
		}
		if !hasPath(out, "POST /admin/delete/<item_id>", "writes items") {
			t.Error("P4 missing")
		}
		if hasRoute(out, "GET /me") || hasRoute(out, "GET /account") {
			t.Error("P2/P5 (SAFE) reported")
		}
	})
}

func TestAttackSurface(t *testing.T) {
	project, _ := brainFixture(t, "vibeapp")
	var out struct {
		Entrypoints  int
		WithoutLogin int `json:"without_login"`
		Datastores   []string
		Items        []struct {
			Route      string
			At         string
			LoginCheck bool `json:"login_check"`
			Writes     []string
			Reads      []string
		}
	}
	json.Unmarshal([]byte(mustCall(t, handleAttackSurface(project), nil)), &out) //nolint:errcheck
	byRoute := map[string]int{}
	for i, it := range out.Items {
		byRoute[it.Route] = i
	}
	orders, ok := byRoute["POST /api/orders"]
	if !ok || out.Items[orders].LoginCheck || len(out.Items[orders].Writes) == 0 || !strings.HasPrefix(out.Items[orders].At, "app/api/orders/route.ts:") {
		t.Errorf("orders entry: %+v", out.Items)
	}
	profile, ok := byRoute["GET /api/profile"]
	if !ok || !out.Items[profile].LoginCheck {
		t.Errorf("profile entry should have a login check: %+v", out.Items)
	}
	if out.Items[0].LoginCheck || profile < orders {
		t.Error("unguarded routes must rank first")
	}
	if !strings.Contains(strings.Join(out.Datastores, ","), "orders") {
		t.Errorf("datastores = %v", out.Datastores)
	}
}

func TestTraceDataflow(t *testing.T) {
	project, _ := brainFixture(t, "vibeapp")
	text := mustCall(t, handleTraceDataflow(project), map[string]any{"target": "/api/orders"})
	for _, want := range []string{`"function":"POST /api/orders"`, `"store":"orders","access":"writes"`, "createClient (lib/supabase/server.ts:", `"reachable_without_login":true`} {
		if !strings.Contains(text, want) {
			t.Errorf("trace /api/orders missing %s: %s", want, text)
		}
	}
	text = mustCall(t, handleTraceDataflow(project), map[string]any{"target": "GET /api/profile"})
	if !strings.Contains(text, `"login_check":true`) || !strings.Contains(text, `"store":"profiles","access":"reads"`) {
		t.Errorf("trace profile: %s", text)
	}
	text = mustCall(t, handleTraceDataflow(project), map[string]any{"target": "deletePost"})
	if !strings.Contains(text, `"store":"posts","access":"writes"`) {
		t.Errorf("trace deletePost: %s", text)
	}
	if text := mustCall(t, handleTraceDataflow(project), map[string]any{"target": "orders"}); !strings.Contains(text, "what_touches") {
		t.Errorf("datastore target should point at what_touches: %s", text)
	}
	if text := mustCall(t, handleTraceDataflow(project), map[string]any{"target": "nope_nothing"}); !strings.Contains(text, "No route or function") {
		t.Errorf("unknown target: %s", text)
	}
}

func TestWhatTouches(t *testing.T) {
	project, root := brainFixture(t, "vibeapp")
	text := mustCall(t, handleWhatTouches(project), map[string]any{"target": "profiles"})
	if !strings.Contains(text, `"function":"GET /api/profile"`) || !strings.Contains(text, "components/AdminPanel.tsx") || !strings.Contains(text, `"client_side":true`) {
		t.Errorf("profiles: %s", text)
	}
	// Exposed code ranks first: the browser delete, not the guarded read.
	if strings.Index(text, "AdminPanel") > strings.Index(text, "GET /api/profile") {
		t.Errorf("profiles not ranked: %s", text)
	}
	if text := mustCall(t, handleWhatTouches(project), map[string]any{"target": "order"}); !strings.Contains(text, `"function":"POST /api/orders"`) || !strings.Contains(text, `"reachable_without_login":true`) {
		t.Errorf("orders: %s", text)
	}
	if text := mustCall(t, handleWhatTouches(project), map[string]any{"target": "payments"}); !strings.Contains(text, "known_datastores") {
		t.Errorf("unknown category should list what exists: %s", text)
	}
	orgcontext.Save(root, &orgcontext.OrgContext{ //nolint:errcheck
		App:           orgcontext.AppInfo{Name: "vibe", Description: "shop"},
		SensitiveData: []orgcontext.SensitiveDataCategory{{Category: "payments", FilePatterns: []string{"app/api/orders/**"}}},
	})
	if text := mustCall(t, handleWhatTouches(project), map[string]any{"target": "payments"}); !strings.Contains(text, `"touches":"category payments"`) || !strings.Contains(text, "app/api/orders/route.ts:") {
		t.Errorf("payments category: %s", text)
	}
}

func TestSecurityRulesPerStack(t *testing.T) {
	cases := map[string][]string{
		"vibeapp":    {"Row Level Security", "service-role client", "supabase.auth.getUser()", "NEXT_PUBLIC_", "STRIPE_SECRET_KEY", "POST /api/orders"},
		"expressapp": {"auth middleware", "requireAuth", "DELETE /api/notes/:id", "pool.query"},
		"pyapp":      {"Depends(get_current_user)", "@login_required", "POST /items", "POST /admin/delete/<item_id>", "cursor.execute"},
	}
	for app, wants := range cases {
		project, _ := brainFixture(t, app)
		text := mustCall(t, handleSecurityRules(project), nil)
		for _, w := range wants {
			if !strings.Contains(text, w) {
				t.Errorf("%s rules missing %q:\n%s", app, w, text)
			}
		}
		if app == "pyapp" && (strings.Contains(text, "GET /me") || strings.Contains(text, "GET /account")) {
			t.Errorf("pyapp: guarded routes listed as broken")
		}
		if app == "vibeapp" && strings.Contains(text, "GET /api/profile") {
			t.Errorf("vibeapp: guarded profile route listed as broken")
		}
	}
	project, _ := brainFixture(t, "vibeapp")
	text := mustCall(t, handleSecurityRules(project), map[string]any{"area": "client"})
	if strings.Contains(text, `"area":"auth"`) || !strings.Contains(text, `"area":"client"`) {
		t.Errorf("area filter: %s", text)
	}
	if _, isErr := callTool(t, handleSecurityRules(project), map[string]any{"area": "bogus"}); !isErr {
		t.Error("bad area should error")
	}
}

// TestSuppressRemembersFalsePositive: suppress_finding records a false
// positive, the next scan's get_findings hides it, and
// include_false_positives shows it again.
func TestSuppressRemembersFalsePositive(t *testing.T) {
	project, root := brainFixture(t, "vibeapp")
	scan := func() {
		if _, err := normalizer.SaveScanResult(root, []normalizer.Finding{
			{ID: "fp1", Severity: normalizer.SeverityHigh, Title: "SQLi", RuleID: "js.sqli", FilePath: "app/api/export/route.ts", LineNumber: 5, Status: normalizer.StatusOpen},
			{ID: "ok1", Severity: normalizer.SeverityHigh, Title: "Unauth write", RuleID: "js.noauth", FilePath: "app/api/orders/route.ts", LineNumber: 7, Status: normalizer.StatusOpen},
		}); err != nil {
			t.Fatal(err)
		}
	}
	shown := func(args map[string]any) []string {
		var out struct{ Findings []struct{ ID string } }
		json.Unmarshal([]byte(mustCall(t, handleGetFindings(project), args)), &out) //nolint:errcheck
		var ids []string
		for _, f := range out.Findings {
			ids = append(ids, f.ID)
		}
		return ids
	}
	scan()
	mustCall(t, handleUpdateStatus(project, normalizer.StatusSuppressed), map[string]any{"id": "fp1", "reason": "false alarm: the query is a constant"})

	store, err := memory.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	fps, _ := store.FalsePositives()
	store.Close()
	if len(fps) != 1 || fps[0].File != "app/api/export/route.ts" || fps[0].RuleID != "js.sqli" || !strings.Contains(fps[0].Evidence, "constant") {
		t.Fatalf("memory false positives = %+v", fps)
	}

	scan() // a later scan reports the same finding as open again
	if ids := shown(nil); len(ids) != 1 || ids[0] != "ok1" {
		t.Errorf("default get_findings = %v, want only ok1", ids)
	}
	if ids := shown(map[string]any{"include_false_positives": true}); len(ids) != 2 {
		t.Errorf("include_false_positives = %v, want both", ids)
	}

	// Accepting a risk and marking fixed are remembered with their own kinds.
	mustCall(t, handleUpdateStatus(project, normalizer.StatusSuppressed), map[string]any{"id": "ok1", "reason": "the user accepts this risk"})
	mustCall(t, handleUpdateStatus(project, normalizer.StatusResolved), map[string]any{"id": "ok1"})
	text := mustCall(t, handleSecurityHistory(project), map[string]any{"file": "app/api/orders/route.ts"})
	if !strings.Contains(text, `"kind":"accepted_risk"`) || !strings.Contains(text, `"kind":"fixed"`) || strings.Contains(text, "export") {
		t.Errorf("history for orders route: %s", text)
	}
	if text := mustCall(t, handleSecurityHistory(project), map[string]any{"rule": "js.sqli"}); !strings.Contains(text, `"kind":"false_positive"`) {
		t.Errorf("history by rule: %s", text)
	}
}

func TestSecurityHistoryEmpty(t *testing.T) {
	project, _ := brainFixture(t, "pyapp")
	if text := mustCall(t, handleSecurityHistory(project), nil); !strings.Contains(text, "no history") {
		t.Errorf("empty history: %s", text)
	}
}

func TestGetFindingsShowsExposure(t *testing.T) {
	project, root := brainFixture(t, "vibeapp")
	findings := []normalizer.Finding{
		{ID: "a", Severity: normalizer.SeverityHigh, Title: "in profile", FilePath: "app/api/profile/route.ts", LineNumber: 8, Status: normalizer.StatusOpen},
		{ID: "b", Severity: normalizer.SeverityHigh, Title: "in orders", FilePath: "app/api/orders/route.ts", LineNumber: 7, Status: normalizer.StatusOpen},
	}
	// The scan hook (as ScanOnce runs it).
	if err := reach.Enrich(root, findings); err != nil {
		t.Fatal(err)
	}
	normalizer.SaveScanResult(root, findings) //nolint:errcheck
	text := mustCall(t, handleGetFindings(project), nil)
	if !strings.Contains(text, "public route, no login check; writes orders") || !strings.Contains(text, "behind login; reads profiles") {
		t.Errorf("exposure missing: %s", text)
	}
	if strings.Index(text, `"id": "b"`) > strings.Index(text, `"id": "a"`) {
		t.Errorf("exposed finding should rank first within a severity: %s", text)
	}
}

type fakeEmbedder struct{}

func (fakeEmbedder) Embed(texts []string, _ string) ([][]float32, error) {
	out := make([][]float32, len(texts))
	for i := range texts {
		out[i] = []float32{1, 0}
	}
	return out, nil
}

func TestSearchCodeSecurity(t *testing.T) {
	project, root := brainFixture(t, "vibeapp")
	text, isErr := callTool(t, handleSearchCodeSecurity(project), map[string]any{"query": "where are orders written"})
	if isErr || !strings.Contains(text, "trojan index") {
		t.Errorf("no index: %v %s", isErr, text)
	}

	store, _ := rag.Load(root)
	store.Upsert("app/api/orders/route.ts", "h", []rag.Entry{{
		Chunk:  rag.Chunk{FilePath: "app/api/orders/route.ts", StartLine: 4, EndLine: 9, Symbol: "POST", Text: `await supabase.from("orders").insert(body)`},
		Vector: []float32{1, 0},
	}})
	if err := store.Save(root); err != nil {
		t.Fatal(err)
	}
	old := newEmbedder
	newEmbedder = func(string) rag.Embedder { return fakeEmbedder{} }
	defer func() { newEmbedder = old }()
	text = mustCall(t, handleSearchCodeSecurity(project), map[string]any{"query": "where are orders written"})
	if !strings.Contains(text, `"at":"app/api/orders/route.ts:4-9"`) {
		t.Errorf("search: %s", text)
	}
}

// TestBrainToolsUnderSizeCap runs every brain tool on the Trojan repo itself
// and checks each response stays under 8 KB.
func TestBrainToolsUnderSizeCap(t *testing.T) {
	if testing.Short() {
		t.Skip("builds the graph of the whole repo")
	}
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	project := func(context.Context, mcp.CallToolRequest) (string, error) { return root, nil }
	calls := []struct {
		name string
		h    func(context.Context, mcp.CallToolRequest) (*mcp.CallToolResult, error)
		args map[string]any
	}{
		{"get_attack_surface", handleAttackSurface(project), nil},
		{"get_attack_paths", handleAttackPaths(project), nil},
		{"trace_dataflow", handleTraceDataflow(project), map[string]any{"target": "handle"}},
		{"trace_dataflow", handleTraceDataflow(project), map[string]any{"target": "/api/latest-scan"}},
		{"what_touches", handleWhatTouches(project), map[string]any{"target": "orders"}},
		{"what_touches", handleWhatTouches(project), map[string]any{"target": "profiles"}},
		{"get_security_rules", handleSecurityRules(project), nil},
		{"get_security_history", handleSecurityHistory(project), nil},
		{"search_code_security", handleSearchCodeSecurity(project), map[string]any{"query": "auth"}},
	}
	for _, c := range calls {
		text, _ := callTool(t, c.h, c.args)
		t.Logf("%s %v: %d bytes", c.name, c.args, len(text))
		if len(text) >= 8*1024 {
			t.Errorf("%s response is %d bytes, over 8 KB", c.name, len(text))
		}
	}
}

// TestFitJSONShrinksToCap: a list far over the cap is shortened until the
// response fits, and says it was truncated.
func TestFitJSONShrinksToCap(t *testing.T) {
	items := make([]string, 2000)
	for i := range items {
		items[i] = strings.Repeat("x", 40)
	}
	res := fitJSON(len(items), func(n int) any {
		return map[string]any{"items": capN(items, n), "truncated": n < len(items)}
	})
	text := res.Content[0].(mcp.TextContent).Text
	if len(text) > maxResponseBytes || !strings.Contains(text, `"truncated":true`) {
		t.Errorf("fitJSON: %d bytes, %s", len(text), text[:80])
	}
}
