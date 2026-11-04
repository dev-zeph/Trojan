package agent

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// loginServer is a fake app: POST /login with the right email+password sets a
// session cookie (and redirects, to prove cookie capture survives a redirect).
func loginServer(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.FormValue("email") == "amara@example.com" && r.FormValue("password") == "welcome123" {
			http.SetCookie(w, &http.Cookie{Name: "session", Value: "sess-abc-123", Path: "/"})
			http.Redirect(w, r, "/dashboard", http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK) // wrong creds: no cookie
	})
	mux.HandleFunc("/dashboard", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })
	return httptest.NewServer(mux)
}

func TestResolveIdentities_LoginRecipe(t *testing.T) {
	srv := loginServer(t)
	defer srv.Close()

	ids := []Identity{{
		Name:  "client-a",
		Login: &LoginRecipe{URL: srv.URL + "/login", Fields: map[string]string{"email": "amara@example.com", "password": "welcome123"}},
	}}

	out, err := ResolveIdentities(context.Background(), ids, srv.Client())
	if err != nil {
		t.Fatalf("ResolveIdentities: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("got %d identities, want 1", len(out))
	}
	got := out[0]
	if c := got.Headers["Cookie"]; !strings.Contains(c, "session=sess-abc-123") {
		t.Errorf("Cookie header = %q, want it to contain session=sess-abc-123", c)
	}
	if got.Login != nil {
		t.Error("Login recipe should be cleared after resolution (must not carry the password forward)")
	}
	if !strings.Contains(got.Source, "logged in via") {
		t.Errorf("Source = %q, want a 'logged in via …' label", got.Source)
	}
	// The password must never appear in anything the agent/model can see.
	if strings.Contains(got.Source, "welcome123") {
		t.Error("Source leaked the password")
	}
}

func TestResolveIdentities_HeaderIdentityPassesThrough(t *testing.T) {
	ids := []Identity{{Name: "raw", Headers: map[string]string{"Authorization": "Bearer xyz"}}}
	out, err := ResolveIdentities(context.Background(), ids, nil)
	if err != nil {
		t.Fatalf("ResolveIdentities: %v", err)
	}
	if out[0].Headers["Authorization"] != "Bearer xyz" {
		t.Errorf("header identity was altered: %+v", out[0])
	}
}

func TestResolveIdentities_NoCookieIsError(t *testing.T) {
	srv := loginServer(t)
	defer srv.Close()

	ids := []Identity{{
		Name:  "bad",
		Login: &LoginRecipe{URL: srv.URL + "/login", Fields: map[string]string{"email": "amara@example.com", "password": "WRONG"}},
	}}
	if _, err := ResolveIdentities(context.Background(), ids, srv.Client()); err == nil {
		t.Fatal("expected an error when login sets no session cookie, got nil")
	}
}
