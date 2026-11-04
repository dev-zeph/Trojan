package agent

import (
	"context"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"time"
)

// ResolveIdentities turns any identity carrying a LoginRecipe into a ready-to-use
// header identity by performing the login and capturing the session cookie.
// Identities that already have Headers (a raw cookie/token, or an earlier
// capture) pass through unchanged.
//
// Security: the target app's credentials are used only here, on this machine, to
// obtain a session. They are dropped from the returned identity (Login is
// cleared) — only the resulting Cookie header travels on, and the agent/model
// sees just the identity name and a secret-free Source label.
func ResolveIdentities(ctx context.Context, ids []Identity, client *http.Client) ([]Identity, error) {
	if client == nil {
		client = &http.Client{Timeout: 20 * time.Second}
	}
	out := make([]Identity, len(ids))
	for i, id := range ids {
		if id.Login == nil || len(id.Headers) > 0 {
			out[i] = id
			continue
		}
		label := loginLabel(id.Login)
		cookie, err := performLogin(ctx, client, id.Login)
		if err != nil {
			return nil, fmt.Errorf("identity %q: %w", id.Name, err)
		}
		id.Headers = map[string]string{"Cookie": cookie}
		id.Login = nil // don't carry the recipe (and its secret) any further
		id.Source = "logged in via " + label
		out[i] = id
	}
	return out, nil
}

// performLogin submits the recipe's fields (form-encoded) to its URL and returns
// a "k=v; k2=v2" Cookie header built from whatever session cookie(s) the login
// set — captured via a private cookie jar so a post-login redirect still works.
func performLogin(ctx context.Context, client *http.Client, r *LoginRecipe) (string, error) {
	if strings.TrimSpace(r.URL) == "" {
		return "", fmt.Errorf("login recipe has no url")
	}
	method := strings.ToUpper(strings.TrimSpace(r.Method))
	if method == "" {
		method = http.MethodPost
	}
	form := url.Values{}
	for k, v := range r.Fields {
		form.Set(k, v)
	}

	jar, err := cookiejar.New(nil)
	if err != nil {
		return "", err
	}
	c := *client // shallow copy so we can attach a private jar without mutating the caller's client
	c.Jar = jar

	req, err := http.NewRequestWithContext(ctx, method, r.URL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.Do(req)
	if err != nil {
		return "", fmt.Errorf("login request failed: %w", err)
	}
	defer resp.Body.Close()

	u, err := url.Parse(r.URL)
	if err != nil {
		return "", err
	}
	cookies := jar.Cookies(u)
	if len(cookies) == 0 {
		return "", fmt.Errorf("login returned HTTP %d but set no session cookie — check the credentials and the login URL/field names", resp.StatusCode)
	}
	parts := make([]string, 0, len(cookies))
	for _, ck := range cookies {
		parts = append(parts, ck.Name+"="+ck.Value)
	}
	return strings.Join(parts, "; "), nil
}

// loginLabel renders a secret-free "POST /login" label for Identity.Source.
func loginLabel(r *LoginRecipe) string {
	m := strings.ToUpper(strings.TrimSpace(r.Method))
	if m == "" {
		m = "POST"
	}
	path := r.URL
	if u, err := url.Parse(r.URL); err == nil && u.Path != "" {
		path = u.Path
	}
	return m + " " + path
}
