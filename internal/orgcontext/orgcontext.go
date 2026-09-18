// Package orgcontext defines Trojan's authored org-context overlay: what the
// user says their app does, what sensitive data it handles, where its trust
// boundaries sit, and who they are defending against.
//
// This authored context is the highest-leverage input the AI gets. A generic
// heuristic can guess a variable named "ssn" is PII; only the user can say
// "this internal admin tool is only reachable by employees, but a malicious
// tenant is still a threat actor we care about." ApplyOverlay layers that
// stated model onto the Code Property Graph (internal/graph) built by
// graph.BuildFromGoFiles, so downstream reasoning (report copy, the agent
// loop, path ranking) reflects the org's own model instead of only generic
// heuristics.
//
// The schema is authored by hand (or scaffolded via WriteScaffold) as YAML at
// .trojan/context.yaml, project-local alongside other Trojan project state.
// This package only defines the schema, loads it, and applies it to a graph;
// it does not persist anything itself and does not talk to the AI loop (both
// are owned elsewhere).
package orgcontext

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// DefaultRelPath is where the org-context file lives, relative to a project
// root.
const DefaultRelPath = ".trojan/context.yaml"

// AppInfo describes what the app is and does, in the user's own words.
type AppInfo struct {
	// Name is the app's name, used in report copy ("threat model for X").
	Name string `yaml:"name"`
	// Description is a one-paragraph, free-text explanation of what the app
	// is, who uses it, and why it exists. This is the single highest-value
	// field in the whole schema: it is what lets Trojan test intentionally
	// instead of generically.
	Description string `yaml:"description"`
}

// SensitiveDataCategory names one category of sensitive data the app handles
// (PII, PHI, payment, credentials, ...) and the patterns that locate it in
// code. ApplyOverlay marks any graph node matching one of these patterns as
// PII and tags it with the category name.
type SensitiveDataCategory struct {
	// Category is a short label, e.g. "PII", "PHI", "payment", "credentials".
	Category string `yaml:"category"`
	// Description is optional free text, e.g. "Customer names and emails".
	Description string `yaml:"description,omitempty"`
	// FilePatterns are glob-like path patterns (supporting "*" and "**")
	// matched against a node's source file, e.g. "internal/billing/**".
	FilePatterns []string `yaml:"file_patterns,omitempty"`
	// SymbolPatterns are regexes matched against a node's name (a function's
	// package-qualified symbol, or a sink's callee expression).
	SymbolPatterns []string `yaml:"symbol_patterns,omitempty"`
}

// TrustBoundary names a zone of trust (public API, internal admin, ...) and
// the patterns that locate code living inside it. ApplyOverlay tags matching
// graph nodes with the boundary's name.
type TrustBoundary struct {
	// Name identifies the boundary, e.g. "public API", "internal admin".
	Name string `yaml:"name"`
	// Description is optional free text explaining the boundary.
	Description string `yaml:"description,omitempty"`
	// FilePatterns are glob-like path patterns matched against a node's
	// source file.
	FilePatterns []string `yaml:"file_patterns,omitempty"`
	// SymbolPatterns are regexes matched against a node's name, useful for
	// route/handler naming conventions (e.g. "(?i)^Handle").
	SymbolPatterns []string `yaml:"symbol_patterns,omitempty"`
}

// ThreatActor names who the user is defending against, and, optionally, which
// trust boundaries that actor is assumed to be able to reach.
type ThreatActor struct {
	// Name identifies the actor, e.g. "external attacker", "malicious
	// tenant", "insider".
	Name string `yaml:"name"`
	// Description is optional free text about this actor's capabilities.
	Description string `yaml:"description,omitempty"`
	// Targets lists TrustBoundary.Name values this actor is assumed to be
	// able to reach. Purely descriptive metadata for now (consumed by the AI
	// loop and reporting, not by ApplyOverlay).
	Targets []string `yaml:"targets,omitempty"`
}

// OrgContext is the authored, organization-level model of a codebase: what it
// is, what data it protects, where its boundaries are, and who threatens it.
// It is deliberately small and hand-written, not inferred.
type OrgContext struct {
	App             AppInfo                 `yaml:"app"`
	SensitiveData   []SensitiveDataCategory `yaml:"sensitive_data,omitempty"`
	TrustBoundaries []TrustBoundary         `yaml:"trust_boundaries,omitempty"`
	ThreatActors    []ThreatActor           `yaml:"threat_actors,omitempty"`
}

// Path returns the project-local context file path for a project root
// (DefaultRelPath joined onto root).
func Path(root string) string {
	return filepath.Join(root, DefaultRelPath)
}

// Exists reports whether a context file is present at path.
func Exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// Load reads and parses an org-context YAML file from disk.
func Load(path string) (*OrgContext, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("orgcontext: read %s: %w", path, err)
	}
	var ctx OrgContext
	if err := yaml.Unmarshal(data, &ctx); err != nil {
		return nil, fmt.Errorf("orgcontext: parse %s: %w", path, err)
	}
	return &ctx, nil
}
