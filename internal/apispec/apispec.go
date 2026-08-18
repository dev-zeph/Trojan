// Package apispec ingests an OpenAPI/Swagger description of a target's HTTP API
// and turns it into a flat list of operations (§6.5 #4, schema ingestion). It is
// the completeness lever for the agentic pen-test: the crawler only finds
// endpoints reachable by following links, while a spec declares the WHOLE
// surface — versioned/admin routes with no UI link, the parameters each endpoint
// takes, and which endpoints declare authentication. Those become extra attack
// surface for the agent (merged into the crawl map by the composition root).
//
// Parsing is deliberately tolerant and map-based rather than struct-based: specs
// in the wild carry vendor extensions, mixed drafts, and partial fields, and a
// strict decoder rejects too many real documents. The package is pure Go and
// CGO-free (JSON via encoding/json, YAML via yaml.v3 — both decode to the same
// map[string]any shape), so it doesn't disturb the desktop cross-compile.
package apispec

import (
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Operation is one endpoint declared by a spec.
type Operation struct {
	Method      string   `json:"method"`       // upper-case HTTP method
	Path        string   `json:"path"`         // spec path template incl. base, e.g. /api/v2/orders/{id}
	OperationID string   `json:"operation_id"` // spec operationId, when present
	Summary     string   `json:"summary"`      // spec summary/description, trimmed
	QueryParams []string `json:"query_params"` // declared query parameter names
	PathParams  []string `json:"path_params"`  // declared path parameter names
	BodyFields  []string `json:"body_fields"`  // top-level request-body property names (inline schemas)
	Secured     bool     `json:"secured"`      // an auth requirement applies (operation or global)
}

// Spec is the parsed, flattened API surface.
type Spec struct {
	Title   string
	Version string // spec/document version string
	Format  string // "openapi3" | "swagger2"
	Ops     []Operation
}

// httpMethods are the operation keys we recognize under a path item.
var httpMethods = []string{"get", "post", "put", "patch", "delete", "options", "head"}

// DiscoveryPaths are the conventional URLs where an unauthenticated spec is often
// exposed, tried in order during auto-discovery.
func DiscoveryPaths() []string {
	return []string{
		"/openapi.json", "/openapi.yaml",
		"/swagger.json", "/swagger/v1/swagger.json",
		"/v3/api-docs", "/api-docs", "/api/openapi.json",
	}
}

// Parse decodes an OpenAPI 3 or Swagger 2 document (JSON or YAML) into a Spec.
func Parse(data []byte) (*Spec, error) {
	root, err := decode(data)
	if err != nil {
		return nil, err
	}

	spec := &Spec{}
	base := ""
	switch {
	case strings.HasPrefix(str(root["openapi"]), "3"):
		spec.Format = "openapi3"
		base = openAPI3Base(root)
	case strings.HasPrefix(str(root["swagger"]), "2"):
		spec.Format = "swagger2"
		base = str(root["basePath"])
	default:
		return nil, fmt.Errorf("not a recognized OpenAPI 3 or Swagger 2 document (missing/unknown openapi|swagger version)")
	}
	base = strings.TrimRight(base, "/")

	if info, ok := root["info"].(map[string]any); ok {
		spec.Title = str(info["title"])
		spec.Version = str(info["version"])
	}

	// A document-level security requirement is the default unless an operation
	// overrides it (including overriding with an explicit empty requirement).
	globalSecured := nonEmptyArray(root["security"])

	paths, _ := root["paths"].(map[string]any)
	for _, p := range sortedKeys(paths) {
		item, ok := paths[p].(map[string]any)
		if !ok {
			continue
		}
		// Path-level parameters apply to every operation under the path item.
		pathQuery, pathPath := params(item["parameters"])
		for _, m := range httpMethods {
			opRaw, ok := item[m].(map[string]any)
			if !ok {
				continue
			}
			op := Operation{
				Method:      strings.ToUpper(m),
				Path:        joinBase(base, p),
				OperationID: str(opRaw["operationId"]),
				Summary:     summaryOf(opRaw),
			}
			q, pp := params(opRaw["parameters"])
			op.QueryParams = dedupe(append(pathQuery, q...))
			op.PathParams = dedupe(append(pathPath, pp...))
			op.BodyFields = bodyFields(opRaw, spec.Format)
			op.Secured = operationSecured(opRaw, globalSecured)
			spec.Ops = append(spec.Ops, op)
		}
	}
	return spec, nil
}

// decode parses JSON or YAML into a generic map. JSON is tried first (it is the
// common spec encoding and its decoder is stricter); YAML — a JSON superset — is
// the fallback. yaml.v3 decodes string-keyed maps to map[string]any, matching
// encoding/json, so downstream navigation is identical for both.
func decode(data []byte) (map[string]any, error) {
	var root map[string]any
	if json.Unmarshal(data, &root) == nil && root != nil {
		return root, nil
	}
	if err := yaml.Unmarshal(data, &root); err != nil {
		return nil, fmt.Errorf("spec is neither valid JSON nor YAML: %w", err)
	}
	if root == nil {
		return nil, fmt.Errorf("spec is empty")
	}
	return root, nil
}

// openAPI3Base extracts the path portion of the first server URL, which prefixes
// every declared path (e.g. servers[0].url = https://api.x.com/v2 → "/v2").
func openAPI3Base(root map[string]any) string {
	servers, ok := root["servers"].([]any)
	if !ok || len(servers) == 0 {
		return ""
	}
	s0, ok := servers[0].(map[string]any)
	if !ok {
		return ""
	}
	raw := str(s0["url"])
	if raw == "" {
		return ""
	}
	if u, err := url.Parse(raw); err == nil && u.Path != "" {
		return u.Path // handles both absolute URLs and bare "/v2" paths
	}
	return ""
}

// params splits a spec "parameters" array into query- and path-parameter names.
// Body/header/cookie params are ignored here (body is handled separately).
func params(raw any) (query, path []string) {
	arr, ok := raw.([]any)
	if !ok {
		return nil, nil
	}
	for _, p := range arr {
		m, ok := p.(map[string]any)
		if !ok {
			continue
		}
		name := str(m["name"])
		if name == "" {
			continue
		}
		switch str(m["in"]) {
		case "query":
			query = append(query, name)
		case "path":
			path = append(path, name)
		}
	}
	return query, path
}

// bodyFields returns the top-level property names of an operation's request body
// for inline schemas. $ref-ed schemas are not resolved in v1 (returns none for
// those) — the endpoint still surfaces, just without body-shape hints.
func bodyFields(op map[string]any, format string) []string {
	var schema map[string]any
	if format == "openapi3" {
		rb, ok := op["requestBody"].(map[string]any)
		if !ok {
			return nil
		}
		content, ok := rb["content"].(map[string]any)
		if !ok {
			return nil
		}
		// Prefer JSON, else take any media type present.
		mt, ok := content["application/json"].(map[string]any)
		if !ok {
			for _, v := range content {
				if m, ok := v.(map[string]any); ok {
					mt = m
					break
				}
			}
		}
		schema, _ = mt["schema"].(map[string]any)
	} else {
		// Swagger 2: a body parameter carries the schema; formData params are fields.
		if arr, ok := op["parameters"].([]any); ok {
			var formFields []string
			for _, p := range arr {
				m, ok := p.(map[string]any)
				if !ok {
					continue
				}
				switch str(m["in"]) {
				case "body":
					schema, _ = m["schema"].(map[string]any)
				case "formData":
					if n := str(m["name"]); n != "" {
						formFields = append(formFields, n)
					}
				}
			}
			if len(formFields) > 0 {
				return dedupe(formFields)
			}
		}
	}
	props, ok := schema["properties"].(map[string]any)
	if !ok {
		return nil
	}
	return sortedKeys(props)
}

// operationSecured reports whether an auth requirement applies to the operation.
// An operation-level "security" key overrides the global default — including an
// explicit empty array, which deliberately marks the operation as public.
func operationSecured(op map[string]any, globalSecured bool) bool {
	if raw, present := op["security"]; present {
		return nonEmptyArray(raw)
	}
	return globalSecured
}

var normSegment = regexp.MustCompile(`^(\{[^}]*\}|\d+|[0-9a-fA-F-]{8,})$`)

// NormalizePath collapses a path to a shape key for coverage comparison: template
// params, numeric ids, and long hex/uuid segments all become "*", so /users/123
// (crawled) and /users/{id} (spec) compare equal.
func NormalizePath(p string) string {
	segs := strings.Split(p, "/")
	for i, s := range segs {
		if s != "" && normSegment.MatchString(s) {
			segs[i] = "*"
		}
	}
	return strings.Join(segs, "/")
}

// ── small tolerant accessors ──

func str(v any) string {
	if s, ok := v.(string); ok {
		return strings.TrimSpace(s)
	}
	return ""
}

func summaryOf(op map[string]any) string {
	if s := str(op["summary"]); s != "" {
		return s
	}
	return str(op["description"])
}

func nonEmptyArray(v any) bool {
	arr, ok := v.([]any)
	return ok && len(arr) > 0
}

func sortedKeys(m map[string]any) []string {
	if len(m) == 0 {
		return nil
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func joinBase(base, p string) string {
	if base == "" {
		return p
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	return base + p
}

func dedupe(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}
