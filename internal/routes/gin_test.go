package routes

import (
	"sort"
	"strings"
	"testing"
)

func TestExtractGin(t *testing.T) {
	dir := t.TempDir()
	mkfile(t, dir, "go.mod", "module x\n\nrequire github.com/gin-gonic/gin v1.9.1")
	mkfile(t, dir, "main.go", `package main

func setup() {
	r := gin.Default()
	r.GET("/health", healthHandler)

	api := r.Group("/api")
	api.POST("/login", loginHandler)

	v1 := api.Group("/v1")
	v1.GET("/users/:id", getUser)
	v1.DELETE("/users/:id", deleteUser)

	r.Any("/webhook", webhookHandler)
	r.GET("/files/*filepath", serveFile)
}
`)

	got := extractGin(dir)
	var keys []string
	for _, r := range got {
		m := r.Method
		if m == "" {
			m = "ANY"
		}
		keys = append(keys, m+" "+r.PathPattern)
	}
	sort.Strings(keys)
	want := []string{
		"ANY /webhook",
		"DELETE /api/v1/users/{id}",
		"GET /api/v1/users/{id}",       // nested groups: r -> /api -> /v1
		"GET /files/{filepath...}",     // *filepath catch-all
		"GET /health",
		"POST /api/login",
	}
	if strings.Join(keys, "\n") != strings.Join(want, "\n") {
		t.Errorf("gin routes:\n got:\n  %s\nwant:\n  %s",
			strings.Join(keys, "\n  "), strings.Join(want, "\n  "))
	}

	// Nested-group resolution + handler symbol.
	for _, r := range got {
		if r.Method == "GET" && r.PathPattern == "/api/v1/users/{id}" && r.HandlerSymbol != "getUser" {
			t.Errorf("handler symbol = %q, want getUser", r.HandlerSymbol)
		}
	}
}

func TestGinResolvesViaResolver(t *testing.T) {
	dir := t.TempDir()
	mkfile(t, dir, "go.mod", "module x\nrequire github.com/gin-gonic/gin v1.9.1")
	mkfile(t, dir, "main.go", `package main
func s() {
	r := gin.New()
	api := r.Group("/api")
	api.GET("/users/:id", getUser)
}
`)
	res := NewResolver(dir)
	if res.Framework() != FrameworkGin {
		t.Fatalf("framework = %q, want gin", res.Framework())
	}
	got, ok := res.Resolve("GET", "/api/users/7")
	if !ok || got.PathPattern != "/api/users/{id}" {
		t.Errorf("resolve -> %q (ok=%v), want /api/users/{id}", got.PathPattern, ok)
	}
}
