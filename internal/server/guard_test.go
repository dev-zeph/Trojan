package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestLocalGuard(t *testing.T) {
	ok := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	h := localGuard(ok)
	cases := []struct {
		name, method, host, origin string
		want                       int
		wantACAO                   string
	}{
		{"no origin (curl, AI tools)", "GET", "127.0.0.1:5555", "", 200, ""},
		{"desktop app macOS", "POST", "127.0.0.1:5555", "tauri://localhost", 200, "tauri://localhost"},
		{"desktop app Windows", "GET", "127.0.0.1:5555", "http://tauri.localhost", 200, "http://tauri.localhost"},
		{"desktop dev server", "GET", "127.0.0.1:5555", "http://localhost:1420", 200, "http://localhost:1420"},
		{"report page itself", "POST", "127.0.0.1:5555", "http://127.0.0.1:5555", 200, "http://127.0.0.1:5555"},
		{"desktop preflight", "OPTIONS", "127.0.0.1:5555", "tauri://localhost", 204, "tauri://localhost"},
		{"other website", "GET", "127.0.0.1:5555", "https://evil.example", 403, ""},
		{"other website preflight", "OPTIONS", "127.0.0.1:5555", "https://evil.example", 403, ""},
		{"other local port", "POST", "127.0.0.1:5555", "http://127.0.0.1:8080", 403, ""},
		{"DNS rebinding", "GET", "evil.example:5555", "", 403, ""},
		{"localhost host", "GET", "localhost:5555", "", 200, ""},
	}
	for _, c := range cases {
		req := httptest.NewRequest(c.method, "/api/scans/latest", nil)
		req.Host = c.host
		if c.origin != "" {
			req.Header.Set("Origin", c.origin)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != c.want {
			t.Errorf("%s: status %d, want %d", c.name, rec.Code, c.want)
		}
		if got := rec.Header().Get("Access-Control-Allow-Origin"); got != c.wantACAO {
			t.Errorf("%s: ACAO %q, want %q", c.name, got, c.wantACAO)
		}
	}
}
