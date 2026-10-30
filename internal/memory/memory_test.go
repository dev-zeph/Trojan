package memory

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dev-zeph/trojan/internal/normalizer"
)

func openTemp(t *testing.T) (*Store, string) {
	t.Helper()
	root := t.TempDir()
	s, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s, root
}

func TestRoundTrip(t *testing.T) {
	s, _ := openTemp(t)
	evs := []Event{
		{Kind: KindConfirmed, NodeKey: "k1", File: "a/b.go", RuleID: "r1", Title: "t1", Evidence: "e1", Source: SourceAgent},
		{Kind: KindFalsePositive, NodeKey: "k2", File: "a/c.go", RuleID: "r2", Title: "t2", Evidence: "test fixture", Source: SourceUser},
		{Kind: KindFact, NodeKey: "k1", File: "a/b.go", Title: "no ownership check", Source: SourceClaude},
	}
	for _, e := range evs {
		if err := s.Record(e); err != nil {
			t.Fatal(err)
		}
	}
	got, err := s.ForKey("k1")
	if err != nil || len(got) != 2 {
		t.Fatalf("ForKey: %v %v", got, err)
	}
	if got[0].Title != "t1" || got[0].Evidence != "e1" || got[0].Source != SourceAgent || got[0].At.IsZero() {
		t.Fatalf("bad round trip: %+v", got[0])
	}
	if got, _ = s.ForFile("a/c.go"); len(got) != 1 || got[0].Kind != KindFalsePositive {
		t.Fatalf("ForFile: %v", got)
	}
	if got, _ = s.FalsePositives(); len(got) != 1 || got[0].NodeKey != "k2" {
		t.Fatalf("FalsePositives: %v", got)
	}
	if got, _ = s.ForKey("nope"); len(got) != 0 {
		t.Fatalf("expected none: %v", got)
	}
	if all, _ := s.All(); len(all) != 3 {
		t.Fatalf("All: %d", len(all))
	}
	if ok, err := s.Delete(KindFact, "k1", "a/b.go", ""); err != nil || !ok {
		t.Fatalf("Delete: %v %v", ok, err)
	}
	if all, _ := s.All(); len(all) != 2 {
		t.Fatalf("All after delete: %d", len(all))
	}
}

func TestDedupe(t *testing.T) {
	s, _ := openTemp(t)
	t1 := time.Now().Add(-time.Hour)
	t2 := time.Now()
	base := Event{Kind: KindConfirmed, NodeKey: "k", File: "f.go", RuleID: "r", Title: "old", Evidence: "one", Source: SourceScanner, At: t1}
	if err := s.Record(base); err != nil {
		t.Fatal(err)
	}
	base.Evidence, base.Title, base.At = "two", "new", t2
	if err := s.Record(base); err != nil {
		t.Fatal(err)
	}
	got, _ := s.ForKey("k")
	if len(got) != 1 {
		t.Fatalf("want 1 row, got %d", len(got))
	}
	if got[0].Evidence != "two" || got[0].Title != "new" || !got[0].At.Equal(t2) {
		t.Fatalf("not updated: %+v", got[0])
	}
	// A different kind is a different identity.
	base.Kind = KindFixed
	if err := s.Record(base); err != nil {
		t.Fatal(err)
	}
	if got, _ = s.ForKey("k"); len(got) != 2 {
		t.Fatalf("want 2 rows, got %d", len(got))
	}
}

func TestConcurrentWriters(t *testing.T) {
	root := t.TempDir()
	// Two handles on the same file stand in for two processes.
	a, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()

	const n = 250
	var wg sync.WaitGroup
	errs := make(chan error, 2*n)
	for _, w := range []struct {
		s   *Store
		tag string
	}{{a, "a"}, {b, "b"}} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < n; i++ {
				e := Event{Kind: KindFact, NodeKey: fmt.Sprintf("%s-%d", w.tag, i), File: "x.go", Title: "t", Source: SourceAgent}
				if err := w.s.Record(e); err != nil {
					errs <- err
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent write failed: %v", err)
	}
	all, err := a.All()
	if err != nil || len(all) != 2*n {
		t.Fatalf("want %d rows, got %d (%v)", 2*n, len(all), err)
	}
}

func TestOpenCreatesDBAndGitignore(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	s, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := os.Stat(filepath.Join(root, DefaultDBPath)); err != nil {
		t.Fatalf("db not created: %v", err)
	}
	gi, err := os.ReadFile(filepath.Join(root, ".gitignore"))
	if err != nil || !strings.Contains(string(gi), ".trojan") {
		t.Fatalf(".trojan not gitignored: %q %v", gi, err)
	}
	// Reopening an existing db works and keeps data.
	if err := s.Record(Event{Kind: KindFact, Title: "x", Source: SourceUser}); err != nil {
		t.Fatal(err)
	}
	s.Close()
	s2, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	if all, _ := s2.All(); len(all) != 1 {
		t.Fatalf("data lost on reopen: %d", len(all))
	}
}

func TestEventFromFindingAndIsFalsePositive(t *testing.T) {
	s, root := openTemp(t)
	abs := filepath.Join(root, "src", "api", "x.ts")
	f := normalizer.Finding{Scanner: "semgrep", RuleID: "sqli", FilePath: abs, LineNumber: 4, Title: "SQL injection"}

	e := EventFromFinding(f, KindFalsePositive, SourceUser, root)
	if e.File != "src/api/x.ts" || e.RuleID != "sqli" || e.Title != "SQL injection" || e.Kind != KindFalsePositive || e.Source != SourceUser {
		t.Fatalf("bad event: %+v", e)
	}
	// Already-relative and out-of-root paths.
	if e := EventFromFinding(normalizer.Finding{FilePath: "./a\\b.go"}, KindFact, SourceScanner, root); e.File != "a/b.go" {
		t.Fatalf("relative not normalized: %q", e.File)
	}
	if e := EventFromFinding(normalizer.Finding{FilePath: "/elsewhere/z.go"}, KindFact, SourceScanner, root); e.File != "/elsewhere/z.go" {
		t.Fatalf("out-of-root changed: %q", e.File)
	}

	if ok, err := s.IsFalsePositive(f); err != nil || ok {
		t.Fatalf("expected not FP yet: %v %v", ok, err)
	}
	if err := s.Record(e); err != nil {
		t.Fatal(err)
	}
	if ok, err := s.IsFalsePositive(f); err != nil || !ok {
		t.Fatalf("expected FP: %v %v", ok, err)
	}
	// Relative form of the same finding also matches; other rule does not.
	g := f
	g.FilePath = "src/api/x.ts"
	if ok, _ := s.IsFalsePositive(g); !ok {
		t.Fatal("relative path should match")
	}
	g.RuleID = "xss"
	if ok, _ := s.IsFalsePositive(g); ok {
		t.Fatal("different rule must not match")
	}
}
