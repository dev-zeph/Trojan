// Package fingerprint collects a local, code-free summary of a project (its
// framework, dependencies, routes, data stores, env var NAMES, auth libraries)
// so Trojan can infer what the app handles without sending source code.
// Env var values and file contents never enter a Fingerprint.
package fingerprint

// RouteSummary is one HTTP entrypoint.
type RouteSummary struct {
	Method string `json:"method"`
	Path   string `json:"path"`
	File   string `json:"file"` // project-relative
}

// GraphSummary is a count-level view of the code graph, when one exists.
type GraphSummary struct {
	Entrypoints       int      `json:"entrypoints"`
	UnguardedEntries  int      `json:"unguarded_entrypoints"`
	DataStores        []string `json:"data_stores,omitempty"`
	ClientSideSecrets int      `json:"client_side_secrets"`
}

// Fingerprint is what Trojan can tell about a project without reading code
// contents out of it.
type Fingerprint struct {
	Framework     string         `json:"framework,omitempty"` // "nextjs", "express", "fastapi", "flask", ...
	Languages     []string       `json:"languages,omitempty"`
	Dependencies  []string       `json:"dependencies,omitempty"`
	ThirdParty    []string       `json:"third_party,omitempty"` // services inferred from deps, e.g. "stripe", "supabase"
	Routes        []RouteSummary `json:"routes,omitempty"`
	DataStores    []string       `json:"data_stores,omitempty"` // e.g. table names from migrations / schema
	EnvVarNames   []string       `json:"env_var_names,omitempty"`
	AuthLibraries []string       `json:"auth_libraries,omitempty"`
	Outline       []string       `json:"outline,omitempty"` // capped list of notable project-relative paths
	GraphSummary  *GraphSummary  `json:"graph_summary,omitempty"`
}
