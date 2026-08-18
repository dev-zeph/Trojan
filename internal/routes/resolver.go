package routes

// Resolver maps live URLs to source handlers for one project. It classifies the
// framework and extracts the route table once at construction, then answers
// Resolve() queries against the cached table — the DAST agent resolves many URLs
// per run, so extraction shouldn't repeat.
type Resolver struct {
	projectPath string
	framework   Framework
	routes      []Route
}

// NewResolver classifies the project and extracts its routes. It never fails:
// an unknown or not-yet-supported framework yields an empty table, so Resolve
// simply returns no match (and the caller falls back to black-box behavior or,
// later, the semantic index — §7.1 Tier 2).
func NewResolver(projectPath string) *Resolver {
	fw := Classify(projectPath)
	return &Resolver{
		projectPath: projectPath,
		framework:   fw,
		routes:      extractFor(fw, projectPath),
	}
}

// Resolve returns the handler route for a live (method, urlPath), if the route
// table has one.
func (r *Resolver) Resolve(method, urlPath string) (Route, bool) {
	return Match(r.routes, method, urlPath)
}

// Routes returns the full extracted route table (e.g. for the endpoint↔handler
// map handed to the agent at run start — §6.6 push context).
func (r *Resolver) Routes() []Route { return r.routes }

// Framework reports the detected framework ("" if unknown).
func (r *Resolver) Framework() Framework { return r.framework }

// extractFor dispatches to the framework-specific extractor. Only Next.js is
// implemented in v1 (filesystem-routed, most precise, our stack — §7.5); other
// frameworks return nil until their extractors land (v2/v3).
func extractFor(fw Framework, projectPath string) []Route {
	switch fw {
	case FrameworkNextjs:
		return extractNextjs(projectPath)
	default:
		return nil
	}
}
