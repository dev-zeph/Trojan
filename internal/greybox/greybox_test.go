package greybox

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dev-zeph/trojan/internal/ai"
	"github.com/dev-zeph/trojan/internal/routes"
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

// fakeRetriever implements ai.ContextRetriever.
type fakeRetriever struct{ chunks []ai.RetrievedChunk }

func (f fakeRetriever) Retrieve(query string, k int) ([]ai.RetrievedChunk, error) {
	return f.chunks, nil
}

// TestByEndpoint is the flagship path: a live URL -> handler source + the
// structural read that primes a grounded hypothesis.
func TestByEndpoint(t *testing.T) {
	dir := t.TempDir()
	mkfile(t, dir, "package.json", `{"dependencies":{"next":"14"}}`)
	// Vulnerable handler: raw SQL concat, no auth guard.
	mkfile(t, dir, "app/api/users/[id]/route.ts", `import { db } from '@/db'

export async function GET(req: Request, { params }: any) {
  const id = params.id
  return db.query("SELECT * FROM users WHERE id = " + id)
}
`)

	src := New(dir, routes.NewResolver(dir), nil)
	res, err := src.ReadSource(ReadSourceRequest{Endpoint: &EndpointRef{Method: "GET", Path: "/api/users/42"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Chunks) != 1 {
		t.Fatalf("expected 1 handler chunk, got %d (note=%q)", len(res.Chunks), res.Note)
	}
	c := res.Chunks[0]
	if !strings.Contains(c.Code, "SELECT * FROM users") {
		t.Errorf("handler body not read: %q", c.Code)
	}
	if c.Symbol != "GET" {
		t.Errorf("handler symbol = %q, want GET", c.Symbol)
	}
	if res.Summary == nil || !res.Summary.RawQuery {
		t.Errorf("expected raw_query=true (SQL concat), got %+v", res.Summary)
	}
	if res.Summary.HasAuthCheck {
		t.Errorf("expected has_auth_check=false (no guard), got true — this is the IDOR/SQLi signal")
	}
}

// TestByEndpointWithGuard: a middleware-guarded route reports has_auth_check.
func TestByEndpointWithGuard(t *testing.T) {
	dir := t.TempDir()
	mkfile(t, dir, "package.json", `{"dependencies":{"next":"14"}}`)
	mkfile(t, dir, "app/api/admin/route.ts", "export function GET(){ return listUsers() }")
	mkfile(t, dir, "middleware.ts", "export function middleware(){}") // no matcher -> guards all

	src := New(dir, routes.NewResolver(dir), nil)
	res, _ := src.ReadSource(ReadSourceRequest{Endpoint: &EndpointRef{Method: "GET", Path: "/api/admin"}})
	if res.Summary == nil || !res.Summary.HasAuthCheck {
		t.Errorf("expected has_auth_check=true from middleware guard, got %+v (guards=%v)", res.Summary, res.Guards)
	}
	if len(res.Guards) == 0 {
		t.Errorf("expected guards surfaced, got none")
	}
}

func TestBySymbol(t *testing.T) {
	dir := t.TempDir()
	mkfile(t, dir, "src/auth.go", `package auth

func VerifyOwnership(userID, resourceID string) bool {
	return userID == ownerOf(resourceID)
}
`)
	src := New(dir, nil, nil)
	res, _ := src.ReadSource(ReadSourceRequest{Symbol: "VerifyOwnership"})
	if len(res.Chunks) != 1 {
		t.Fatalf("expected to find the symbol, got %d chunks (note=%q)", len(res.Chunks), res.Note)
	}
	if !strings.Contains(res.Chunks[0].Code, "ownerOf(resourceID)") {
		t.Errorf("symbol body not read: %q", res.Chunks[0].Code)
	}
	if res.Chunks[0].File != "src/auth.go" {
		t.Errorf("file = %q, want src/auth.go", res.Chunks[0].File)
	}
}

func TestByQuery(t *testing.T) {
	dir := t.TempDir()
	ret := fakeRetriever{chunks: []ai.RetrievedChunk{
		{FilePath: "util/sanitize.go", StartLine: 10, EndLine: 14, Text: "func Sanitize(s string) string { return escape(s) }"},
	}}
	src := New(dir, nil, ret)
	res, _ := src.ReadSource(ReadSourceRequest{Query: "input sanitization helper"})
	if len(res.Chunks) != 1 || res.Chunks[0].File != "util/sanitize.go" {
		t.Fatalf("expected the sanitize chunk, got %+v", res.Chunks)
	}
	if res.Summary == nil || !res.Summary.SanitizesInput {
		t.Errorf("expected sanitizes_input=true on the top hit, got %+v", res.Summary)
	}
}

func TestByEndpointNoResolverDegrades(t *testing.T) {
	src := New(t.TempDir(), nil, nil) // no resolver, no retriever
	res, err := src.ReadSource(ReadSourceRequest{Endpoint: &EndpointRef{Method: "GET", Path: "/x"}})
	if err != nil {
		t.Fatalf("should degrade gracefully, not error: %v", err)
	}
	if res.Note == "" {
		t.Errorf("expected an explanatory note when source is unavailable")
	}
	if len(res.Chunks) != 0 {
		t.Errorf("expected no chunks without a resolver")
	}
}

func TestEndpointTable(t *testing.T) {
	dir := t.TempDir()
	mkfile(t, dir, "package.json", `{"dependencies":{"next":"14"}}`)
	mkfile(t, dir, "app/api/open/route.ts", "export function GET(){}")
	mkfile(t, dir, "app/dashboard/page.tsx", "export default function D(){}")

	src := New(dir, routes.NewResolver(dir), nil)
	table := src.EndpointTable()
	if len(table) != 2 {
		t.Fatalf("expected 2 rows, got %d: %v", len(table), table)
	}
	joined := strings.Join(table, "\n")
	if !strings.Contains(joined, "[no-guard]") {
		t.Errorf("expected unguarded endpoints flagged, got:\n%s", joined)
	}
}
