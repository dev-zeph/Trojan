package routes

import "testing"

func TestResolverEndToEnd(t *testing.T) {
	dir := t.TempDir()
	mkfile(t, dir, "package.json", `{"dependencies":{"next":"14"}}`)
	mkfile(t, dir, "app/api/users/[id]/route.ts",
		"export async function GET(){}\nexport async function DELETE(){}")
	mkfile(t, dir, "app/dashboard/page.tsx", "export default function D(){}")
	mkfile(t, dir, "middleware.ts",
		"export function middleware(){}\nexport const config = { matcher: ['/dashboard/:path*','/api/:path*'] }")

	r := NewResolver(dir)
	if r.Framework() != FrameworkNextjs {
		t.Fatalf("framework = %q, want nextjs", r.Framework())
	}

	// The grey-box query: live URL -> handler + guards.
	got, ok := r.Resolve("GET", "/api/users/42")
	if !ok {
		t.Fatal("expected to resolve GET /api/users/42")
	}
	if got.HandlerSymbol != "GET" {
		t.Errorf("handler symbol = %q, want GET", got.HandlerSymbol)
	}
	if got.HandlerFile == "" || got.HandlerLine != 1 {
		t.Errorf("handler location = %s:%d, want app/api/users/[id]/route.ts:1", got.HandlerFile, got.HandlerLine)
	}
	if len(got.Guards) == 0 {
		t.Errorf("expected middleware guard on /api route, got none")
	}
	if got.Confidence != 1.0 || got.Source != "filesystem" {
		t.Errorf("expected filesystem confidence, got conf=%.2f source=%s", got.Confidence, got.Source)
	}

	// Method disambiguation on the same path.
	del, ok := r.Resolve("DELETE", "/api/users/42")
	if !ok || del.HandlerSymbol != "DELETE" {
		t.Errorf("DELETE should resolve to the DELETE handler, got %q (ok=%v)", del.HandlerSymbol, ok)
	}

	// A method the route doesn't export -> no match.
	if _, ok := r.Resolve("POST", "/api/users/42"); ok {
		t.Error("POST should not resolve (route.ts exports only GET/DELETE)")
	}
}

func TestResolverUnknownFramework(t *testing.T) {
	dir := t.TempDir()
	mkfile(t, dir, "package.json", `{"dependencies":{"lodash":"4"}}`)
	r := NewResolver(dir)
	if r.Framework() != FrameworkUnknown {
		t.Errorf("expected unknown framework")
	}
	if _, ok := r.Resolve("GET", "/anything"); ok {
		t.Error("unknown framework should resolve nothing (graceful)")
	}
}
