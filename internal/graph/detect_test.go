package graph

import (
	"path/filepath"
	"strings"
	"testing"
)

// storeapp answer key: internal/testdata/ANSWERS.md, section storeapp.

func storeappDetections(t *testing.T) (*Graph, []Detection) {
	t.Helper()
	g := fixtureGraph(t, "storeapp")
	return g, Detect(g, filepath.Join("..", "testdata", "storeapp"))
}

func sinkIn(g *Graph, relSuffix, rule string) []Node {
	var out []Node
	for _, n := range g.Nodes {
		if n.Kind == KindSink && n.SinkRule == rule && strings.HasSuffix(filepath.ToSlash(n.File), relSuffix) {
			out = append(out, n)
		}
	}
	return out
}

// S1: interpolated login SQL from req.json() is a critical, unauthenticated
// SQL injection.
func TestStoreapp_LoginSQLInjection(t *testing.T) {
	_, ds := storeappDetections(t)
	var got []Detection
	for _, d := range ds {
		if d.Rule == DetectSQLInjection {
			got = append(got, d)
		}
	}
	if len(got) != 1 {
		t.Fatalf("want exactly 1 SQL injection (login), got %d: %+v", len(got), got)
	}
	d := got[0]
	if !strings.HasPrefix(d.Sink.Key, "app/api/auth/login/route.ts#POST@") {
		t.Errorf("SQL injection anchored on %q, want the login POST", d.Sink.Key)
	}
	if d.Severity != "critical" || !d.Unguarded {
		t.Errorf("login SQLi: severity %q unguarded %v, want critical/true", d.Severity, d.Unguarded)
	}
	if !strings.Contains(d.Message, "POST /api/auth/login") {
		t.Errorf("message should name the route: %s", d.Message)
	}
}

// S2-S5: bound parameters, tagged templates (postgres.js, @vercel/postgres,
// db.execute(sql`...`)) and a constant column list are not request-input SQL.
func TestStoreapp_ParameterizedAndTaggedNotFlagged(t *testing.T) {
	g, _ := storeappDetections(t)
	for _, f := range []string{"auth/login-safe/route.ts", "search/route.ts", "stats/route.ts", "report/route.ts"} {
		if s := sinkIn(g, f, RuleSQLFromInput); len(s) > 0 {
			t.Errorf("%s: flagged as SQL from request input: %+v", f, s)
		}
	}
	for _, f := range []string{"auth/login-safe/route.ts", "search/route.ts", "stats/route.ts"} {
		if s := sinkIn(g, f, RuleSQLConcat); len(s) > 0 {
			t.Errorf("%s: parameterized/tagged query flagged as concatenation: %+v", f, s)
		}
	}
	// The constant column list is still visible as concatenation (a graph
	// fact), just not as request input.
	if len(sinkIn(g, "report/route.ts", RuleSQLConcat)) != 1 {
		t.Errorf("report: expected the constant-interpolation concat sink")
	}
}

// S6: the public contact form writes messages, the admin page fetches them
// from /api/admin/messages and renders them with dangerouslySetInnerHTML.
func TestStoreapp_StoredXSSChain(t *testing.T) {
	_, ds := storeappDetections(t)
	var got []Detection
	for _, d := range ds {
		if d.Rule == DetectStoredXSS {
			got = append(got, d)
		}
	}
	if len(got) != 1 {
		t.Fatalf("want exactly 1 stored XSS (admin page), got %d: %+v", len(got), got)
	}
	d := got[0]
	if !strings.HasPrefix(d.Sink.Key, "app/admin/page.tsx#") {
		t.Errorf("stored XSS anchored on %q, want app/admin/page.tsx", d.Sink.Key)
	}
	if d.Store != "messages" || d.Entry.Key != "app/api/contact/route.ts#POST" {
		t.Errorf("chain: store %q writer %q, want messages via contact POST", d.Store, d.Entry.Key)
	}
	if len(d.Readers) == 0 || d.Readers[0].Key != "app/api/admin/messages/route.ts#GET" {
		t.Errorf("chain should go through GET /api/admin/messages, got %+v", d.Readers)
	}
}

// S7: raw HTML of data only logged-in users write is a sink, not a finding.
// S8: sanitized raw HTML is not even a sink. The lazy seed() in lib/db.ts
// must not make every public route a writer of notes.
func TestStoreapp_RawHTMLNegatives(t *testing.T) {
	g, _ := storeappDetections(t)
	if len(sinkIn(g, "app/notes/page.tsx", RuleRawHTML)) != 1 {
		t.Errorf("notes page: expected one raw-HTML sink")
	}
	if s := sinkIn(g, "app/inbox/page.tsx", RuleRawHTML); len(s) > 0 {
		t.Errorf("inbox page: DOMPurify-sanitized value flagged: %+v", s)
	}
	for _, n := range g.Nodes {
		if n.Kind == KindSink && n.SinkRule == RuleRawHTML && n.ClientSide && n.Severity == "high" {
			t.Errorf("raw-HTML sink must stay medium so ClientExposures does not report it as a leaked secret: %+v", n)
		}
	}
}

func TestRawHTMLIsSafe(t *testing.T) {
	for expr, want := range map[string]bool{
		` "<b>hi</b>" `:                true,
		"`<b>${name}</b>`":             false,
		` DOMPurify.sanitize(m.body) `: true,
		` JSON.stringify(jsonLd) `:     true,
		` formatText(m.body) `:         false,
		` post.html `:                  false,
		` sanitizeHtml(comment.text) `: true,
	} {
		if got := rawHTMLIsSafe(expr); got != want {
			t.Errorf("rawHTMLIsSafe(%q) = %v, want %v", expr, got, want)
		}
	}
}

func TestRequestTainted(t *testing.T) {
	body := `
  const { email, password } = await req.json();
  const q = new URL(req.url).searchParams.get("q") ?? "";
  const raw = await request.text();
  const parsed = JSON.parse(raw);
  const { id } = await params;
  const limit = 10;
  const cols = columns.join(", ");`
	got := requestTainted(body)
	for _, n := range []string{"email", "password", "q", "raw", "parsed", "id"} {
		if !got[n] {
			t.Errorf("%s should be tainted", n)
		}
	}
	for _, n := range []string{"limit", "cols"} {
		if got[n] {
			t.Errorf("%s should not be tainted", n)
		}
	}
}

func TestIsSetupFunc(t *testing.T) {
	for _, c := range []struct {
		n    Node
		want bool
	}{
		{Node{Key: "lib/db.ts#seed", Name: "db.ts.seed"}, true},
		{Node{Key: "lib/db.ts#seed.anonymous#1", Name: "db.ts.seed.anonymous#1"}, true},
		{Node{Key: "lib/db.ts#migrate", Name: "db.ts.migrate"}, true},
		{Node{Key: "app/api/contact/route.ts#POST", Name: "route.ts.POST"}, false},
		{Node{Key: "scripts/seed.ts#POST", Name: "seed.ts.POST"}, false},
	} {
		if got := isSetupFunc(c.n); got != c.want {
			t.Errorf("isSetupFunc(%s) = %v, want %v", c.n.Key, got, c.want)
		}
	}
}
