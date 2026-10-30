package reach

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/dev-zeph/trojan/internal/graphstore"
	"github.com/dev-zeph/trojan/internal/normalizer"
	"github.com/dev-zeph/trojan/internal/orgcontext"
)

// copyFixture copies internal/testdata/<app> into a temp dir, so refreshing
// its graph never writes .trojan/ into the repo.
func copyFixture(t *testing.T, app string) string {
	t.Helper()
	src := filepath.Join("..", "testdata", app)
	dst := filepath.Join(t.TempDir(), app)
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
	return dst
}

// lineOf returns the 1-based line in root/rel containing needle.
func lineOf(t *testing.T, root, rel, needle string) int {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(root, rel))
	if err != nil {
		t.Fatal(err)
	}
	for i, l := range strings.Split(string(data), "\n") {
		if strings.Contains(l, needle) {
			return i + 1
		}
	}
	t.Fatalf("%q not in %s", needle, rel)
	return 0
}

func analyzer(t *testing.T, app string) (*Analyzer, string) {
	t.Helper()
	root := copyFixture(t, app)
	g, _, err := LoadGraph(root)
	if err != nil {
		t.Fatal(err)
	}
	return New(g, root), root
}

func TestVibeappReach(t *testing.T) {
	a, root := analyzer(t, "vibeapp")

	orders := a.ForLocation("app/api/orders/route.ts", lineOf(t, root, "app/api/orders/route.ts", `.from("orders").insert`))
	if orders == nil {
		t.Fatal("orders finding not placed")
	}
	if !orders.Reachable || orders.Guarded || !slices.Contains(orders.Writes, "orders") {
		t.Errorf("orders route: want reachable, unguarded, writes orders; got %+v", orders)
	}
	if len(orders.Entrypoints) == 0 || !strings.HasPrefix(orders.Entrypoints[0], "POST /api/orders (app/api/orders/route.ts:") {
		t.Errorf("orders entrypoints = %v", orders.Entrypoints)
	}
	if orders.Priority < 5 {
		t.Errorf("orders priority = %d, want >= 5", orders.Priority)
	}

	profile := a.ForLocation("app/api/profile/route.ts", lineOf(t, root, "app/api/profile/route.ts", `from("profiles")`))
	if profile == nil {
		t.Fatal("profile finding not placed")
	}
	if !profile.Reachable || !profile.Guarded || !slices.Contains(profile.Reads, "profiles") {
		t.Errorf("profile route: want reachable, guarded, reads profiles; got %+v", profile)
	}

	// An absolute path from a scanner resolves the same way.
	abs := a.ForLocation(filepath.Join(root, "app/actions.ts"), lineOf(t, root, "app/actions.ts", `.delete()`))
	if abs == nil || abs.Guarded || !slices.Contains(abs.Writes, "posts") {
		t.Errorf("deletePost: %+v", abs)
	}

	admin := a.ForLocation("components/AdminPanel.tsx", lineOf(t, root, "components/AdminPanel.tsx", `.delete()`))
	if admin == nil || !admin.ClientSide || admin.Priority < 4 {
		t.Errorf("AdminPanel: want client side and exposed priority; got %+v", admin)
	}

	if a.ForLocation("package.json", 3) != nil || a.ForLocation("app/api/orders/route.ts", 0) != nil {
		t.Error("findings outside functions must have no reach")
	}
}

func TestRankPutsExposedFirst(t *testing.T) {
	a, root := analyzer(t, "vibeapp")
	findings := []normalizer.Finding{
		{ID: "dep", FilePath: "package.json", LineNumber: 1},
		{ID: "profile", FilePath: "app/api/profile/route.ts", LineNumber: lineOf(t, root, "app/api/profile/route.ts", `from("profiles")`)},
		{ID: "orders", FilePath: "app/api/orders/route.ts", LineNumber: lineOf(t, root, "app/api/orders/route.ts", `insert`)},
	}
	a.Annotate(findings)
	Rank(findings)
	if findings[0].ID != "orders" || findings[len(findings)-1].ID != "dep" {
		t.Errorf("rank order = %s, %s, %s", findings[0].ID, findings[1].ID, findings[2].ID)
	}
}

func TestLabels(t *testing.T) {
	cases := map[string][]string{
		"vibeapp":    {"POST /api/orders", "GET /api/profile", "GET /api/export", "server action deletePost", "middleware"},
		"expressapp": {"DELETE /api/notes/:id", "GET /api/users/:id", "GET /health"},
		"pyapp":      {"POST /items", "GET /me", "GET /search", "POST /admin/delete/<item_id>", "GET /account"},
	}
	for app, want := range cases {
		a, _ := analyzer(t, app)
		var got []string
		for _, n := range a.G.Nodes {
			if n.Source {
				got = append(got, a.Label(n))
			}
		}
		for _, w := range want {
			if !slices.Contains(got, w) {
				t.Errorf("%s: missing label %q in %v", app, w, got)
			}
		}
	}
}

// TestEnrichRefreshesGraphAndOverlay is the scan-path hook: Enrich builds
// .trojan/graph.db, re-applies context.yaml, and the sensitive category it
// declares shows up on the finding.
func TestEnrichRefreshesGraphAndOverlay(t *testing.T) {
	root := copyFixture(t, "vibeapp")
	if _, err := orgcontext.Save(root, &orgcontext.OrgContext{
		App:           orgcontext.AppInfo{Name: "vibe", Description: "shop"},
		SensitiveData: []orgcontext.SensitiveDataCategory{{Category: "payments", FilePatterns: []string{"app/api/orders/**"}}},
	}); err != nil {
		t.Fatal(err)
	}
	findings := []normalizer.Finding{{ID: "o", FilePath: "app/api/orders/route.ts", LineNumber: lineOf(t, root, "app/api/orders/route.ts", "insert")}}
	if err := Enrich(root, findings); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, graphstore.DefaultDBPath)); err != nil {
		t.Fatalf("graph.db not written: %v", err)
	}
	r := findings[0].Reach
	if r == nil || !r.Sensitive || !slices.Contains(r.Categories, "payments") {
		t.Errorf("overlay not applied: %+v", r)
	}
	// A second Enrich reuses the cache and still re-applies the overlay.
	findings[0].Reach = nil
	if err := Enrich(root, findings); err != nil || findings[0].Reach == nil || !slices.Contains(findings[0].Reach.Categories, "payments") {
		t.Errorf("second enrich: %v %+v", err, findings[0].Reach)
	}
}
