package routes

import "testing"

func TestMatch(t *testing.T) {
	routes := []Route{
		{Method: "GET", PathPattern: "/api/users/{id}", HandlerSymbol: "getUser", Confidence: 1},
		{Method: "GET", PathPattern: "/api/users/me", HandlerSymbol: "getMe", Confidence: 1},
		{Method: "POST", PathPattern: "/api/users/{id}", HandlerSymbol: "updateUser", Confidence: 1},
		{Method: "GET", PathPattern: "/files/{path...}", HandlerSymbol: "serveFile", Confidence: 1},
		{Method: "GET", PathPattern: "/api/users/{id}/posts/{postId}", HandlerSymbol: "getPost", Confidence: 1},
	}

	tests := []struct {
		method, url string
		wantSymbol  string // "" = expect no match
	}{
		{"GET", "/api/users/123", "getUser"},
		{"GET", "/api/users/me", "getMe"},                 // literal beats param
		{"GET", "/api/users/me/", "getMe"},                // trailing slash normalized
		{"POST", "/api/users/123", "updateUser"},          // method disambiguates
		{"DELETE", "/api/users/123", ""},                  // no DELETE route
		{"GET", "/api/users/123/posts/9", "getPost"},      // nested params
		{"GET", "/files/a/b/c.png", "serveFile"},          // catch-all, multi-segment
		{"GET", "/files/x", "serveFile"},                  // catch-all, single segment
		{"GET", "/files", ""},                             // required catch-all needs >=1
		{"GET", "/api/unknown", ""},                       // no match
		{"GET", "/api/users/123?ref=x", "getUser"},        // query stripped
	}
	for _, tt := range tests {
		got, ok := Match(routes, tt.method, tt.url)
		if tt.wantSymbol == "" {
			if ok {
				t.Errorf("%s %s: expected no match, got %s", tt.method, tt.url, got.HandlerSymbol)
			}
			continue
		}
		if !ok || got.HandlerSymbol != tt.wantSymbol {
			t.Errorf("%s %s: got %q (ok=%v), want %q", tt.method, tt.url, got.HandlerSymbol, ok, tt.wantSymbol)
		}
	}
}

func TestMatchOptionalCatchAll(t *testing.T) {
	routes := []Route{{Method: "GET", PathPattern: "/docs/{slug...?}", HandlerSymbol: "docs", Confidence: 1}}
	for _, url := range []string{"/docs", "/docs/a", "/docs/a/b"} {
		if _, ok := Match(routes, "GET", url); !ok {
			t.Errorf("optional catch-all should match %q", url)
		}
	}
}

func TestMatchAnyMethod(t *testing.T) {
	routes := []Route{{Method: "", PathPattern: "/health", HandlerSymbol: "health", Confidence: 1}}
	for _, m := range []string{"GET", "POST", "HEAD"} {
		if _, ok := Match(routes, m, "/health"); !ok {
			t.Errorf("empty method should match any verb %q", m)
		}
	}
}
