package greybox

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dev-zeph/trojan/internal/routes"
)

func nextProject(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	mkfile(t, dir, "package.json", `{"dependencies":{"next":"14"}}`)
	mkfile(t, dir, "app/api/admin/customers/route.ts", `import { db } from '@/lib/db'

// admin search
export async function GET(req: Request) {
  const q = new URL(req.url).searchParams.get("q") ?? ""
  return db.query("SELECT * FROM customers WHERE full_name LIKE '%" + q + "%'")
}
`)
	mkfile(t, dir, "app/api/auth/signup/route.ts", `export async function POST(req: Request) {
  return Response.json({ ok: true })
}
`)
	mkfile(t, dir, "app/api/bookings/[id]/route.ts", `export async function GET() { return Response.json({}) }
`)
	return dir
}

func TestLocate_MapsURLsToHandlers(t *testing.T) {
	dir := nextProject(t)
	src := New(dir, routes.NewResolver(dir), nil)

	cases := []struct {
		method, url, file string
		line              int
	}{
		{"", "http://127.0.0.1:3000/api/admin/customers?q=x", "app/api/admin/customers/route.ts", 4},
		{"", "/api/auth/signup", "app/api/auth/signup/route.ts", 1}, // POST-only: found without a method
		{"", "POST /api/auth/signup", "app/api/auth/signup/route.ts", 1},
		{"", "http://127.0.0.1:3000/api/bookings/{id}", "app/api/bookings/[id]/route.ts", 1},
		{"GET", "http://127.0.0.1:3000/api/bookings/42", "app/api/bookings/[id]/route.ts", 1},
	}
	for _, c := range cases {
		file, line, ok := src.Locate(c.method, c.url)
		if !ok || file != c.file || line != c.line {
			t.Errorf("Locate(%q) = %q:%d ok=%v, want %q:%d", c.url, file, line, ok, c.file, c.line)
		}
	}
	if _, _, ok := src.Locate("", "http://127.0.0.1:3000/nope"); ok {
		t.Error("unknown route located")
	}
	var nilSrc *Source
	if _, _, ok := nilSrc.Locate("", "/api/auth/signup"); ok {
		t.Error("nil source located a route")
	}
}

func TestProjectFile_RefusesPathsOutsideTheProject(t *testing.T) {
	dir := nextProject(t)
	outside := filepath.Join(t.TempDir(), "secret.txt")
	os.WriteFile(outside, []byte("secret"), 0o600)      //nolint:errcheck
	os.Symlink(outside, filepath.Join(dir, "link.txt")) //nolint:errcheck
	src := New(dir, routes.NewResolver(dir), nil)

	if rel, ok := src.ProjectFile("app/api/auth/signup/route.ts"); !ok || rel != "app/api/auth/signup/route.ts" {
		t.Errorf("relative file: %q %v", rel, ok)
	}
	if rel, ok := src.ProjectFile(filepath.Join(dir, "app/api/auth/signup/route.ts")); !ok || rel != "app/api/auth/signup/route.ts" {
		t.Errorf("absolute file inside project: %q %v", rel, ok)
	}
	for _, bad := range []string{"../../etc/passwd", outside, "link.txt", "app/api", "missing.ts", ""} {
		if rel, ok := src.ProjectFile(bad); ok {
			t.Errorf("ProjectFile(%q) accepted as %q", bad, rel)
		}
	}
	if got := src.HandlerSource("../../etc/passwd", 1); got != "" {
		t.Errorf("HandlerSource read outside the project: %q", got)
	}
	if got := src.HandlerSource("app/api/admin/customers/route.ts", 4); !strings.Contains(got, "LIKE") {
		t.Errorf("HandlerSource = %q", got)
	}
}
