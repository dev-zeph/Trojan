package scanners

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dev-zeph/trojan/internal/normalizer"
)

// copyStoreapp copies internal/testdata/storeapp out of testdata (the source
// walker skips testdata directories, as a real scan would).
func copyStoreapp(t *testing.T) string {
	t.Helper()
	src := filepath.Join("..", "testdata", "storeapp")
	dst := filepath.Join(t.TempDir(), "storeapp")
	err := filepath.WalkDir(src, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		if d.IsDir() {
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

func TestGraphChecks_Storeapp(t *testing.T) {
	root := copyStoreapp(t)
	fs, err := GraphChecks{}.Run(root)
	if err != nil {
		t.Fatal(err)
	}
	byRule := map[string][]normalizer.Finding{}
	for _, f := range fs {
		byRule[f.RuleID] = append(byRule[f.RuleID], f)
		if f.Scanner != "trojan" || f.Category != "sast" || f.Status != normalizer.StatusOpen {
			t.Errorf("bad finding shape: %+v", f)
		}
	}
	if len(fs) != 2 {
		t.Fatalf("want 2 findings (login SQLi, admin stored XSS), got %d: %+v", len(fs), fs)
	}
	sqli := byRule["trojan.sql-injection"]
	if len(sqli) != 1 {
		t.Fatalf("sql injection findings: %+v", sqli)
	}
	if f := sqli[0]; f.Severity != normalizer.SeverityCritical ||
		f.FilePath != filepath.Join(root, "app", "api", "auth", "login", "route.ts") ||
		!strings.Contains(f.CodeSnippet, "${email}") || len(f.CWEIDs) != 1 || f.CWEIDs[0] != "CWE-89" {
		t.Errorf("login SQLi finding: %+v", f)
	}
	xss := byRule["trojan.stored-xss"]
	if len(xss) != 1 {
		t.Fatalf("stored XSS findings: %+v", xss)
	}
	if f := xss[0]; f.Severity != normalizer.SeverityHigh ||
		f.FilePath != filepath.Join(root, "app", "admin", "page.tsx") ||
		!strings.Contains(f.CodeSnippet, "dangerouslySetInnerHTML") ||
		!strings.Contains(f.RawMessage, "POST /api/contact") || f.CWEIDs[0] != "CWE-79" {
		t.Errorf("stored XSS finding: %+v", f)
	}
	// Stable ids across runs, so watch mode and verify_fix can track them.
	again, _ := GraphChecks{}.Run(root)
	if len(again) != len(fs) || again[0].ID != fs[0].ID {
		t.Errorf("finding ids not stable across runs")
	}
}

// Fixing the query (bound parameter) and rendering text instead of raw HTML
// clears both findings.
func TestGraphChecks_FixedClears(t *testing.T) {
	root := copyStoreapp(t)
	login := filepath.Join(root, "app", "api", "auth", "login", "route.ts")
	fixedLogin := `import { getDb } from "@/lib/db";

export async function POST(req: Request) {
  const { email, password } = await req.json();
  const user = getDb().prepare("SELECT id, role FROM users WHERE email = ? AND password = ?").get(email, password);
  return Response.json({ user });
}
`
	if err := os.WriteFile(login, []byte(fixedLogin), 0o644); err != nil {
		t.Fatal(err)
	}
	page := filepath.Join(root, "app", "admin", "page.tsx")
	b, _ := os.ReadFile(page)
	fixedPage := strings.Replace(string(b), `<div dangerouslySetInnerHTML={{ __html: formatText(m.body) }} />`, `<div style={{ whiteSpace: "pre-line" }}>{m.body}</div>`, 1)
	if fixedPage == string(b) {
		t.Fatal("fixture changed; update the replacement")
	}
	if err := os.WriteFile(page, []byte(fixedPage), 0o644); err != nil {
		t.Fatal(err)
	}
	fs, err := GraphChecks{}.Run(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 0 {
		t.Errorf("fixed app still reports: %+v", fs)
	}
}

func TestRelevantScannersIncludesGraphChecks(t *testing.T) {
	got := RelevantScanners([]Scanner{GraphChecks{}}, ProjectType{})
	if len(got) != 1 || got[0].Name() != "trojan" {
		t.Errorf("graph checks must always be relevant, got %v", got)
	}
}
