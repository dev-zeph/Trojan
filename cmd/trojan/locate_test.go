package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dev-zeph/trojan/internal/dast/agent"
	"github.com/dev-zeph/trojan/internal/greybox"
	"github.com/dev-zeph/trojan/internal/normalizer"
	"github.com/dev-zeph/trojan/internal/routes"
)

func writeFile(t *testing.T, dir, rel, content string) {
	t.Helper()
	p := filepath.Join(dir, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// (d) A grey-box finding on a route that exists in the project gets a real
// file and non-zero line, while FilePath stays the URL for existing consumers.
func TestLocateWebsiteFindings_GreyBoxRouteGetsFileAndLine(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "package.json", `{"dependencies":{"next":"14"}}`)
	writeFile(t, dir, "app/api/admin/customers/route.ts", `import { db } from "@/lib/db"

export async function GET(req: Request) {
  const q = new URL(req.url).searchParams.get("q") ?? ""
  return db.query("SELECT * FROM customers WHERE full_name LIKE '%" + q + "%'")
}
`)
	writeFile(t, dir, "lib/auth.ts", "import crypto from 'crypto'\nexport function hashPassword(p: string) {\n  return crypto.createHash('md5').update(p).digest('hex')\n}\n")
	gb := greybox.New(dir, routes.NewResolver(dir), nil)

	findings := agenticFindingsFromCandidates([]agent.Candidate{
		// No file from the agent: resolved from the route table.
		{Title: "SQL injection in admin customer search", Severity: "high", URL: "http://127.0.0.1:3000/api/admin/customers?q=", Evidence: "q concatenated into SQL"},
		// The agent named the file and line itself: kept.
		{Title: "Weak password hashing", Severity: "medium", URL: "http://127.0.0.1:3000/api/auth/signup", File: "lib/auth.ts", Line: 3},
		// A path outside the project (e.g. steered by a hostile response): dropped.
		{Title: "Odd", Severity: "low", URL: "http://127.0.0.1:3000/nowhere", File: "../../../etc/passwd", Line: 1},
	})
	baseline := []normalizer.Finding{{ID: "nuclei-0", Category: "dast", Title: "Missing CSP", FilePath: "http://127.0.0.1:3000/api/admin/customers"}}
	all := append(baseline, findings...)

	locateWebsiteFindings(all, gb)

	sqli := all[1]
	if sqli.SourceFile != "app/api/admin/customers/route.ts" || sqli.SourceLine != 3 {
		t.Errorf("route finding located at %q:%d, want app/api/admin/customers/route.ts:3", sqli.SourceFile, sqli.SourceLine)
	}
	if sqli.FilePath != "http://127.0.0.1:3000/api/admin/customers?q=" || sqli.URL != sqli.FilePath {
		t.Errorf("URL fields changed: FilePath=%q URL=%q", sqli.FilePath, sqli.URL)
	}
	if !strings.Contains(sqli.SurroundingCode, "LIKE") {
		t.Errorf("handler code not attached for triage/synthesis: %q", sqli.SurroundingCode)
	}
	if md5 := all[2]; md5.SourceFile != "lib/auth.ts" || md5.SourceLine != 3 {
		t.Errorf("agent-reported location lost: %q:%d", md5.SourceFile, md5.SourceLine)
	}
	if odd := all[3]; odd.SourceFile != "" || odd.SourceLine != 0 || odd.SurroundingCode != "" {
		t.Errorf("outside-project path kept: %+v", odd)
	}
	if n := all[0]; n.URL != n.FilePath || n.SourceFile != "app/api/admin/customers/route.ts" {
		t.Errorf("nuclei finding not located: %+v", n)
	}

	// Black-box: URL is still filled, nothing else.
	bb := agenticFindingsFromCandidates([]agent.Candidate{{Title: "x", URL: "http://h/api/admin/customers"}})
	locateWebsiteFindings(bb, nil)
	if bb[0].URL != "http://h/api/admin/customers" || bb[0].SourceFile != "" {
		t.Errorf("black-box finding: %+v", bb[0])
	}
}
