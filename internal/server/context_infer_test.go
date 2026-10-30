package server

import (
	"encoding/json"
	"errors"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dev-zeph/trojan/internal/ai"
	"github.com/dev-zeph/trojan/internal/fingerprint"
	"github.com/dev-zeph/trojan/internal/orgcontext"
)

type fakeInferer struct {
	res        *ai.InferContextResult
	err        error
	gotDesc    string
	gotExist   *orgcontext.OrgContext
	gotToken   string
	gotProject string
	gotFP      fingerprint.Fingerprint
}

func (f *fakeInferer) Infer(d string, fp fingerprint.Fingerprint, pid string, ex *orgcontext.OrgContext, tok string) (*ai.InferContextResult, error) {
	f.gotDesc, f.gotFP, f.gotProject, f.gotExist, f.gotToken = d, fp, pid, ex, tok
	return f.res, f.err
}

// copyVibeapp copies the planted test app into a temp dir.
func copyVibeapp(t *testing.T) string {
	t.Helper()
	src := filepath.Join("..", "testdata", "vibeapp")
	dst := t.TempDir()
	err := filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		if d.IsDir() {
			return os.MkdirAll(filepath.Join(dst, rel), 0o755)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(dst, rel), b, 0o644)
	})
	if err != nil {
		t.Fatal(err)
	}
	return dst
}

func newInferServer(root string, f *fakeInferer, signedIn bool) *Server {
	s := newTestServerAt(root)
	s.contextInferer = f
	s.authSession = func() (string, string, bool) { return "tok-123", "user-1", signedIn }
	return s
}

func postInfer(s *Server, root, desc string) *httptest.ResponseRecorder {
	body, _ := json.Marshal(map[string]string{"project_path": root, "description": desc})
	rec := httptest.NewRecorder()
	s.handleContextInfer(rec, httptest.NewRequest(http.MethodPost, "/api/context/infer", strings.NewReader(string(body))))
	return rec
}

func TestInfer_ReturnsDraftQuestionsMismatchesFree(t *testing.T) {
	root := copyVibeapp(t)
	f := &fakeInferer{res: &ai.InferContextResult{
		Context:    orgcontext.OrgContext{App: orgcontext.AppInfo{Name: "Shop"}, ThirdPartyServices: []string{"stripe"}},
		Questions:  []string{"Do customers upload files?"},
		Mismatches: []ai.ContextMismatch{{Said: "no payments", Found: "stripe", Question: "Does your app take payments?"}},
		Free:       true,
	}}
	s := newInferServer(root, f, true)

	rec := postInfer(s, root, "A small shop")
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	var out struct {
		Draft      orgcontext.OrgContext `json:"draft"`
		Questions  []string              `json:"questions"`
		Mismatches []ai.ContextMismatch  `json:"mismatches"`
		Free       bool                  `json:"free"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.Draft.App.Name != "Shop" || len(out.Questions) != 1 || len(out.Mismatches) != 1 || !out.Free {
		t.Errorf("unexpected response: %+v", out)
	}
	if f.gotDesc != "A small shop" || f.gotToken != "tok-123" || len(f.gotProject) != 64 || f.gotExist != nil {
		t.Errorf("inferer args wrong: desc=%q tok=%q pid=%q existing=%v", f.gotDesc, f.gotToken, f.gotProject, f.gotExist)
	}
	if f.gotFP.Framework != "nextjs" {
		t.Errorf("fingerprint not collected: %+v", f.gotFP.Framework)
	}
	// Project id depends on the user.
	if projectID(root, "user-1") == projectID(root, "user-2") {
		t.Error("project id should differ per user")
	}
}

func TestInfer_PassesExistingContext(t *testing.T) {
	root := copyVibeapp(t)
	if _, err := orgcontext.Save(root, &orgcontext.OrgContext{App: orgcontext.AppInfo{Name: "Old"}}); err != nil {
		t.Fatal(err)
	}
	f := &fakeInferer{res: &ai.InferContextResult{}}
	postInfer(newInferServer(root, f, true), root, "x")
	if f.gotExist == nil || f.gotExist.App.Name != "Old" {
		t.Errorf("existing context not passed: %+v", f.gotExist)
	}
}

func TestInfer_OutOfTokensMapsTo402(t *testing.T) {
	root := copyVibeapp(t)
	f := &fakeInferer{err: &ai.InsufficientTokensError{Balance: 0}}
	rec := postInfer(newInferServer(root, f, true), root, "x")
	if rec.Code != http.StatusPaymentRequired {
		t.Fatalf("status %d, want 402", rec.Code)
	}
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if out["error"] != "out_of_tokens" || !strings.Contains(out["message"].(string), "out of tokens") {
		t.Errorf("body = %v", out)
	}
}

func TestInfer_OtherErrorAndSignedOut(t *testing.T) {
	root := copyVibeapp(t)
	rec := postInfer(newInferServer(root, &fakeInferer{err: errors.New("boom")}, true), root, "x")
	if rec.Code != http.StatusBadGateway || strings.Contains(rec.Body.String(), "boom") {
		t.Errorf("status %d body %s", rec.Code, rec.Body.String())
	}
	rec = postInfer(newInferServer(root, &fakeInferer{}, false), root, "x")
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("signed out status %d, want 401", rec.Code)
	}
}

func getChanges(s *Server, root string) map[string]any {
	rec := httptest.NewRecorder()
	s.handleContextChanges(rec, httptest.NewRequest(http.MethodGet, "/api/context/changes?project_path="+root, nil))
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return out
}

func TestChanges_DetectsAddedRouteAndTable(t *testing.T) {
	root := copyVibeapp(t)
	s := newTestServerAt(root)

	if out := getChanges(s, root); out["has_snapshot"] != false {
		t.Fatalf("expected no snapshot yet: %v", out)
	}

	// Saving the context stores the snapshot.
	rec := httptest.NewRecorder()
	body := `{"app":{"name":"Shop","description":"d"}}`
	s.handleContext(rec, httptest.NewRequest(http.MethodPost, "/api/context?project_path="+root, strings.NewReader(body)))
	if rec.Code != http.StatusOK {
		t.Fatalf("save: %d %s", rec.Code, rec.Body.String())
	}
	if _, ok := fingerprint.LoadSnapshot(root); !ok {
		t.Fatal("snapshot not written on save")
	}
	if out := getChanges(s, root); out["has_snapshot"] != true || out["changed"] != false {
		t.Fatalf("expected unchanged: %v", out)
	}

	// Add a route and a table.
	if err := os.MkdirAll(filepath.Join(root, "app/api/refunds"), 0o755); err != nil {
		t.Fatal(err)
	}
	route := "export async function POST(req: Request) { return Response.json({}); }\n"
	if err := os.WriteFile(filepath.Join(root, "app/api/refunds/route.ts"), []byte(route), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "supabase/migrations/0002_refunds.sql"), []byte("create table refunds (id int);\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	out := getChanges(s, root)
	if out["changed"] != true {
		t.Fatalf("expected changed: %v", out)
	}
	ch := out["changes"].(map[string]any)
	if !anyHas(ch["routes_added"], "POST /api/refunds") {
		t.Errorf("routes_added = %v", ch["routes_added"])
	}
	if !anyHas(ch["data_stores_added"], "refunds") {
		t.Errorf("data_stores_added = %v", ch["data_stores_added"])
	}
}

func anyHas(v any, want string) bool {
	l, _ := v.([]any)
	for _, x := range l {
		if x == want {
			return true
		}
	}
	return false
}
