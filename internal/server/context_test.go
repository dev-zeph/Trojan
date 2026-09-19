package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/dev-zeph/trojan/internal/normalizer"
	"github.com/dev-zeph/trojan/internal/orgcontext"
)

// newTestServerAt returns a test server whose "active project" is root, the
// same way a real server's active project follows the most recent scan's
// ProjectPath.
func newTestServerAt(root string) *Server {
	return New(&normalizer.ScanResult{ProjectPath: root}, nil)
}

func TestHandleContext_GetNoContext(t *testing.T) {
	root := t.TempDir()
	s := newTestServerAt(root)

	rec := httptest.NewRecorder()
	s.handleContext(rec, httptest.NewRequest(http.MethodGet, "/api/context", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var got contextGetResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if got.Exists {
		t.Error("exists = true, want false when no context.yaml is present")
	}
	if got.Context != nil {
		t.Errorf("context = %+v, want nil", got.Context)
	}
}

func TestHandleContext_PostThenGet(t *testing.T) {
	root := t.TempDir()
	s := newTestServerAt(root)

	body := `{
		"app": {"name": "Acme Billing", "description": "Handles invoices."},
		"sensitive_data": [{"category": "PII", "symbol_patterns": ["(?i)email"]}],
		"trust_boundaries": [{"name": "public API", "file_patterns": ["internal/api/**"]}],
		"threat_actors": [{"name": "external attacker", "targets": ["public API"]}]
	}`

	rec := httptest.NewRecorder()
	s.handleContext(rec, httptest.NewRequest(http.MethodPost, "/api/context", strings.NewReader(body)))
	if rec.Code != http.StatusOK {
		t.Fatalf("POST status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var postResp contextPostResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &postResp); err != nil {
		t.Fatalf("decode POST response: %v", err)
	}
	if !postResp.OK {
		t.Error("ok = false, want true")
	}
	wantPath := orgcontext.Path(root)
	if !strings.HasSuffix(postResp.Path, wantPath) {
		// postResp.Path is absolute; wantPath may already be absolute since
		// t.TempDir() returns an absolute path, so they should match exactly.
		if postResp.Path != wantPath {
			t.Errorf("path = %q, want %q (or to end with it)", postResp.Path, wantPath)
		}
	}

	// GET should now report the saved context.
	rec = httptest.NewRecorder()
	s.handleContext(rec, httptest.NewRequest(http.MethodGet, "/api/context", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var getResp contextGetResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &getResp); err != nil {
		t.Fatalf("decode GET response: %v", err)
	}
	if !getResp.Exists {
		t.Fatal("exists = false, want true after POST")
	}
	if getResp.Context == nil {
		t.Fatal("context = nil, want the saved context")
	}
	if getResp.Context.App.Name != "Acme Billing" {
		t.Errorf("App.Name = %q, want %q", getResp.Context.App.Name, "Acme Billing")
	}
	if len(getResp.Context.SensitiveData) != 1 || getResp.Context.SensitiveData[0].Category != "PII" {
		t.Errorf("SensitiveData = %+v, want one PII entry", getResp.Context.SensitiveData)
	}
}

func TestHandleContext_PostBadJSON(t *testing.T) {
	root := t.TempDir()
	s := newTestServerAt(root)

	rec := httptest.NewRecorder()
	s.handleContext(rec, httptest.NewRequest(http.MethodPost, "/api/context", strings.NewReader("not json")))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
}

func TestHandleContext_MethodNotAllowed(t *testing.T) {
	root := t.TempDir()
	s := newTestServerAt(root)

	rec := httptest.NewRecorder()
	s.handleContext(rec, httptest.NewRequest(http.MethodDelete, "/api/context", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405; body=%s", rec.Code, rec.Body.String())
	}
}

// TestHandleContext_PostWriteFailure proves a 500 surfaces when Save cannot
// write to the active project root (here, a path that does not exist and
// whose parent is unwritable is hard to construct portably, so instead we
// point the "active project" at a location where .trojan cannot be created
// because a file already occupies that name).
func TestHandleContext_PostWriteFailure(t *testing.T) {
	root := t.TempDir()
	// Create a regular file at .trojan so MkdirAll(.trojan) fails.
	blockerPath := root + "/.trojan"
	if err := os.WriteFile(blockerPath, []byte("blocker"), 0o644); err != nil {
		t.Fatalf("setup: %v", err)
	}

	s := newTestServerAt(root)
	rec := httptest.NewRecorder()
	s.handleContext(rec, httptest.NewRequest(http.MethodPost, "/api/context", strings.NewReader(`{"app":{"name":"x","description":"y"}}`)))
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500; body=%s", rec.Code, rec.Body.String())
	}
}
