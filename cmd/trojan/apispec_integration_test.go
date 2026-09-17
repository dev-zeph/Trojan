package main

import (
	"strings"
	"testing"

	"github.com/dev-zeph/trojan/internal/apispec"
	"github.com/dev-zeph/trojan/internal/dast"
)

func TestMergeSpecEndpoints(t *testing.T) {
	// The crawler already reached GET /users/1 — the spec's GET /users/{id} is the
	// same shape and must NOT be added again. Everything else is new surface.
	crawl := &dast.CrawlResult{
		Endpoints: []dast.Endpoint{
			{URL: "http://localhost:3000/users/1", Method: "GET"},
		},
	}
	spec := &apispec.Spec{
		Format: "openapi3",
		Ops: []apispec.Operation{
			{Method: "GET", Path: "/users/{id}", PathParams: []string{"id"}, Secured: true},
			{Method: "DELETE", Path: "/admin/users/{id}", PathParams: []string{"id"}, Secured: false},
			{Method: "POST", Path: "/orders", BodyFields: []string{"item", "qty"}, Secured: true},
		},
	}

	added, notCrawled := mergeSpecEndpoints(crawl, "http://localhost:3000", spec)
	if added != 2 || notCrawled != 2 {
		t.Fatalf("want 2 added / 2 not-crawled, got %d / %d", added, notCrawled)
	}
	// Original + 2 spec endpoints (the duplicate GET /users/{id} was skipped).
	if len(crawl.Endpoints) != 3 {
		t.Fatalf("want 3 endpoints after merge, got %d", len(crawl.Endpoints))
	}

	byURL := map[string]dast.Endpoint{}
	for _, e := range crawl.Endpoints {
		byURL[e.Method+" "+e.URL] = e
	}
	if _, ok := byURL["DELETE http://localhost:3000/admin/users/{id}"]; !ok {
		t.Errorf("templated admin endpoint not merged: %v", byURL)
	}
	post, ok := byURL["POST http://localhost:3000/orders"]
	if !ok {
		t.Fatal("POST /orders not merged")
	}
	if strings.Join(post.FormFields, ",") != "item,qty" {
		t.Errorf("body fields not carried onto endpoint: %v", post.FormFields)
	}
	// The format is recorded as a tech hint.
	if !contains(crawl.TechHints, "openapi3") {
		t.Errorf("openapi3 tech hint missing: %v", crawl.TechHints)
	}
}

func TestSpecTaskHintPrioritizesRisky(t *testing.T) {
	spec := &apispec.Spec{
		Format: "openapi3",
		Ops: []apispec.Operation{
			{Method: "GET", Path: "/health", Secured: true},                                  // boring, goes last
			{Method: "GET", Path: "/admin/config", Secured: false},                           // no-auth → lead
			{Method: "GET", Path: "/orders/{id}", PathParams: []string{"id"}, Secured: true}, // id-param → lead
		},
	}
	hint := specTaskHint(spec)
	iAdmin := strings.Index(hint, "/admin/config")
	iOrders := strings.Index(hint, "/orders/{id}")
	iHealth := strings.Index(hint, "/health")
	if iAdmin < 0 || iOrders < 0 || iHealth < 0 {
		t.Fatalf("hint missing endpoints:\n%s", hint)
	}
	// Risky endpoints (no-auth / id-param) must precede the boring secured one.
	if iAdmin > iHealth || iOrders > iHealth {
		t.Errorf("risky endpoints should lead the hint:\n%s", hint)
	}
	if !strings.Contains(hint, "[no-auth-declared]") || !strings.Contains(hint, "[id-param: id]") {
		t.Errorf("risk flags missing from hint:\n%s", hint)
	}
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
