package apispec

import "testing"

const openapi3JSON = `{
  "openapi": "3.0.1",
  "info": {"title": "Orders API", "version": "2.1.0"},
  "servers": [{"url": "https://api.example.com/v2"}],
  "security": [{"bearerAuth": []}],
  "paths": {
    "/orders/{orderId}": {
      "get": {
        "operationId": "getOrder",
        "summary": "Fetch an order",
        "parameters": [
          {"name": "orderId", "in": "path", "required": true},
          {"name": "expand", "in": "query"}
        ]
      }
    },
    "/admin/users": {
      "post": {
        "operationId": "createUser",
        "requestBody": {
          "content": {
            "application/json": {
              "schema": {"type": "object", "properties": {"email": {}, "role": {}}}
            }
          }
        }
      },
      "get": {"operationId": "listUsers", "security": []}
    }
  }
}`

func opByID(spec *Spec, id string) *Operation {
	for i := range spec.Ops {
		if spec.Ops[i].OperationID == id {
			return &spec.Ops[i]
		}
	}
	return nil
}

func TestParseOpenAPI3(t *testing.T) {
	spec, err := Parse([]byte(openapi3JSON))
	if err != nil {
		t.Fatal(err)
	}
	if spec.Format != "openapi3" || spec.Title != "Orders API" {
		t.Fatalf("unexpected header: format=%q title=%q", spec.Format, spec.Title)
	}
	if len(spec.Ops) != 3 {
		t.Fatalf("want 3 operations, got %d", len(spec.Ops))
	}

	get := opByID(spec, "getOrder")
	if get == nil {
		t.Fatal("getOrder missing")
	}
	// Base path from servers[0].url must prefix the declared path.
	if get.Path != "/v2/orders/{orderId}" {
		t.Errorf("base path not applied: %q", get.Path)
	}
	if len(get.PathParams) != 1 || get.PathParams[0] != "orderId" {
		t.Errorf("path params wrong: %v", get.PathParams)
	}
	if len(get.QueryParams) != 1 || get.QueryParams[0] != "expand" {
		t.Errorf("query params wrong: %v", get.QueryParams)
	}
	if !get.Secured {
		t.Error("getOrder should inherit the global bearerAuth requirement")
	}

	create := opByID(spec, "createUser")
	if create == nil || create.Method != "POST" {
		t.Fatal("createUser missing or wrong method")
	}
	if len(create.BodyFields) != 2 || create.BodyFields[0] != "email" || create.BodyFields[1] != "role" {
		t.Errorf("body fields wrong: %v", create.BodyFields)
	}

	// An explicit empty security array marks the operation public, overriding global.
	list := opByID(spec, "listUsers")
	if list == nil {
		t.Fatal("listUsers missing")
	}
	if list.Secured {
		t.Error("listUsers has security:[] and must be treated as unsecured (override)")
	}
}

const swagger2YAML = `
swagger: "2.0"
info:
  title: Legacy API
  version: 1.0.0
basePath: /api
paths:
  /login:
    post:
      operationId: login
      parameters:
        - name: body
          in: body
          schema:
            type: object
            properties:
              username: {}
              password: {}
  /profile:
    get:
      operationId: profile
`

func TestParseSwagger2YAML(t *testing.T) {
	spec, err := Parse([]byte(swagger2YAML))
	if err != nil {
		t.Fatal(err)
	}
	if spec.Format != "swagger2" {
		t.Fatalf("want swagger2, got %q", spec.Format)
	}
	login := opByID(spec, "login")
	if login == nil {
		t.Fatal("login missing")
	}
	if login.Path != "/api/login" {
		t.Errorf("basePath not applied: %q", login.Path)
	}
	if len(login.BodyFields) != 2 {
		t.Errorf("swagger body params should yield 2 fields, got %v", login.BodyFields)
	}
	// No global or operation security → unsecured.
	if profile := opByID(spec, "profile"); profile == nil || profile.Secured {
		t.Errorf("profile should be unsecured: %+v", profile)
	}
}

func TestParseRejectsUnknown(t *testing.T) {
	if _, err := Parse([]byte(`{"paths": {}}`)); err == nil {
		t.Error("a document with no openapi/swagger version should be rejected")
	}
	if _, err := Parse([]byte(`::: not json or yaml :::`)); err == nil {
		t.Error("garbage input should error")
	}
}

func TestNormalizePath(t *testing.T) {
	cases := map[string]string{
		"/users/123":                         "/users/*",
		"/users/{id}":                        "/users/*",
		"/orders/9c85b0e2-1f3a-4c7d-bb11-aa": "/orders/*",
		"/v2/orders/{orderId}/items":         "/v2/orders/*/items",
		"/static/path":                       "/static/path",
	}
	for in, want := range cases {
		if got := NormalizePath(in); got != want {
			t.Errorf("NormalizePath(%q) = %q, want %q", in, got, want)
		}
	}
}
