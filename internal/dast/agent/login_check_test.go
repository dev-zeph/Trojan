package agent

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCheckLogin(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm() //nolint:errcheck
		switch r.FormValue("password") {
		case "right":
			http.SetCookie(w, &http.Cookie{Name: "s", Value: "1", Path: "/"})
			http.Redirect(w, r, "/dashboard", http.StatusFound)
		case "flash": // failed login that still sets a cookie and re-renders the form
			http.SetCookie(w, &http.Cookie{Name: "s", Value: "flash", Path: "/"})
			w.Write([]byte(`<input type="password" name="password">`)) //nolint:errcheck
		case "bounce": // failed login redirecting back to the login page
			http.SetCookie(w, &http.Cookie{Name: "s", Value: "2", Path: "/"})
			http.Redirect(w, r, "/login?error=1", http.StatusFound)
		default: // no cookie at all
			w.Write([]byte("bad")) //nolint:errcheck
		}
	}))
	defer srv.Close()

	for pw, wantOK := range map[string]bool{"right": true, "flash": false, "bounce": false, "nope": false} {
		lc := CheckLogin(context.Background(), nil, &LoginRecipe{URL: srv.URL + "/login", Fields: map[string]string{"email": "a@x", "password": pw}})
		if lc.OK != wantOK {
			t.Errorf("password %q: OK=%v (%s), want %v", pw, lc.OK, lc.Detail, wantOK)
		}
		if strings.Contains(lc.Detail, pw) || strings.Contains(lc.Detail, "a@x") {
			t.Errorf("detail leaks credentials: %s", lc.Detail)
		}
	}
	if lc := CheckLogin(context.Background(), nil, &LoginRecipe{}); lc.OK {
		t.Error("empty recipe should fail")
	}
}
