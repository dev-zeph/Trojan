package routes

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func mkfile(t *testing.T, dir, rel, content string) {
	t.Helper()
	p := filepath.Join(dir, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// routeKey renders a route as "METHOD path" for compact assertions.
func routeKey(r Route) string {
	m := r.Method
	if m == "" {
		m = "ANY"
	}
	return m + " " + r.PathPattern
}

func TestExtractNextjs_AppRouter(t *testing.T) {
	dir := t.TempDir()
	mkfile(t, dir, "package.json", `{"dependencies":{"next":"14"}}`)
	mkfile(t, dir, "app/page.tsx", "export default function Home(){}")
	mkfile(t, dir, "app/api/users/[id]/route.ts",
		"export async function GET(){}\nexport async function POST(){}")
	mkfile(t, dir, "app/(marketing)/about/page.tsx", "export default function About(){}")
	mkfile(t, dir, "app/dashboard/[...slug]/page.tsx", "export default function D(){}")
	mkfile(t, dir, "app/docs/[[...path]]/route.ts", "export const GET = () => {}")
	mkfile(t, dir, "app/_internal/page.tsx", "export default function P(){}") // private, skip
	mkfile(t, dir, "app/layout.tsx", "export default function L(){}")         // not an endpoint

	got := extractNextjs(dir)
	var keys []string
	for _, r := range got {
		keys = append(keys, routeKey(r))
	}
	sort.Strings(keys)

	want := []string{
		"GET /",
		"GET /about",              // route group (marketing) dropped
		"GET /api/users/{id}",
		"GET /dashboard/{slug...}",
		"GET /docs/{path...?}",    // optional catch-all; route.ts exports GET only
		"POST /api/users/{id}",
	}
	sort.Strings(want)

	if strings.Join(keys, "\n") != strings.Join(want, "\n") {
		t.Errorf("routes mismatch:\n got:\n  %s\nwant:\n  %s", strings.Join(keys, "\n  "), strings.Join(want, "\n  "))
	}

	// Private folder must not produce a route.
	for _, r := range got {
		if strings.Contains(r.PathPattern, "_internal") {
			t.Errorf("private folder leaked into routes: %s", r.PathPattern)
		}
	}
	// Handler line captured for route methods.
	for _, r := range got {
		if r.HandlerSymbol == "POST" && r.HandlerLine != 2 {
			t.Errorf("POST handler line = %d, want 2", r.HandlerLine)
		}
	}
}

func TestExtractNextjs_PagesRouter(t *testing.T) {
	dir := t.TempDir()
	mkfile(t, dir, "package.json", `{"dependencies":{"next":"13"}}`)
	mkfile(t, dir, "pages/index.tsx", "export default function Home(){}")
	mkfile(t, dir, "pages/about.tsx", "export default function About(){}")
	mkfile(t, dir, "pages/api/login.ts", "export default function handler(){}")
	mkfile(t, dir, "pages/api/users/[id].ts", "export default function handler(){}")
	mkfile(t, dir, "pages/_app.tsx", "export default function App(){}") // skip

	got := extractNextjs(dir)
	var keys []string
	for _, r := range got {
		keys = append(keys, routeKey(r))
	}
	sort.Strings(keys)
	want := []string{
		"ANY /api/login",
		"ANY /api/users/{id}",
		"GET /",
		"GET /about",
	}
	if strings.Join(keys, "\n") != strings.Join(want, "\n") {
		t.Errorf("pages routes mismatch:\n got:  %v\nwant: %v", keys, want)
	}
}

func TestExtractNextjs_MiddlewareGuards(t *testing.T) {
	dir := t.TempDir()
	mkfile(t, dir, "package.json", `{"dependencies":{"next":"14"}}`)
	mkfile(t, dir, "app/dashboard/page.tsx", "export default function D(){}")
	mkfile(t, dir, "app/api/public/route.ts", "export function GET(){}")
	mkfile(t, dir, "middleware.ts",
		"export function middleware(){}\nexport const config = { matcher: ['/dashboard/:path*'] }")

	got := extractNextjs(dir)
	guardsByPath := map[string][]string{}
	for _, r := range got {
		guardsByPath[r.PathPattern] = r.Guards
	}
	if len(guardsByPath["/dashboard"]) == 0 {
		t.Errorf("/dashboard should be guarded by middleware, got %v", guardsByPath["/dashboard"])
	}
	if len(guardsByPath["/api/public"]) != 0 {
		t.Errorf("/api/public is outside the matcher; should have no guard, got %v", guardsByPath["/api/public"])
	}
}

func TestExtractNextjs_MiddlewareNoMatcherGuardsAll(t *testing.T) {
	dir := t.TempDir()
	mkfile(t, dir, "package.json", `{"dependencies":{"next":"14"}}`)
	mkfile(t, dir, "app/a/page.tsx", "export default function A(){}")
	mkfile(t, dir, "app/b/page.tsx", "export default function B(){}")
	mkfile(t, dir, "middleware.ts", "export function middleware(){}")

	for _, r := range extractNextjs(dir) {
		if len(r.Guards) == 0 {
			t.Errorf("with no matcher, all routes should be guarded; %s has none", r.PathPattern)
		}
	}
}
