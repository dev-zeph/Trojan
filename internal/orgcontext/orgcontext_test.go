package orgcontext

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/dev-zeph/trojan/internal/graph"
)

const sampleYAML = `
app:
  name: "Acme Billing API"
  description: >
    Billing API for a B2B SaaS product. Handles subscription plans, invoicing,
    and stored payment methods for enterprise customers.

sensitive_data:
  - category: PII
    description: "Customer contact info"
    symbol_patterns:
      - "(?i)email"
  - category: payment
    description: "Stored payment method data"
    file_patterns:
      - "internal/billing/**"

trust_boundaries:
  - name: "public API"
    description: "Internet-facing HTTP handlers"
    symbol_patterns:
      - "(?i)^api\\.Handle"
  - name: "internal admin"
    file_patterns:
      - "internal/admin/**"

threat_actors:
  - name: "external attacker"
    description: "Unauthenticated internet user"
    targets: ["public API"]
  - name: "insider"
    description: "Employee misusing internal admin access"
    targets: ["internal admin"]
`

// TestLoad_ParsesSampleContext proves the schema round-trips through YAML
// with the fields the schema promises.
func TestLoad_ParsesSampleContext(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "context.yaml")
	if err := os.WriteFile(path, []byte(sampleYAML), 0o600); err != nil {
		t.Fatal(err)
	}

	ctx, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if ctx.App.Name != "Acme Billing API" {
		t.Errorf("App.Name = %q", ctx.App.Name)
	}
	if ctx.App.Description == "" {
		t.Error("App.Description is empty")
	}
	if len(ctx.SensitiveData) != 2 {
		t.Fatalf("len(SensitiveData) = %d, want 2", len(ctx.SensitiveData))
	}
	if ctx.SensitiveData[0].Category != "PII" {
		t.Errorf("SensitiveData[0].Category = %q", ctx.SensitiveData[0].Category)
	}
	if len(ctx.TrustBoundaries) != 2 {
		t.Fatalf("len(TrustBoundaries) = %d, want 2", len(ctx.TrustBoundaries))
	}
	if len(ctx.ThreatActors) != 2 {
		t.Fatalf("len(ThreatActors) = %d, want 2", len(ctx.ThreatActors))
	}
	if ctx.ThreatActors[0].Targets[0] != "public API" {
		t.Errorf("ThreatActors[0].Targets = %v", ctx.ThreatActors[0].Targets)
	}
}

// TestLoad_MissingFile reports a wrapped error, not a panic.
func TestLoad_MissingFile(t *testing.T) {
	_, err := Load(filepath.Join(t.TempDir(), "does-not-exist.yaml"))
	if err == nil {
		t.Fatal("expected an error for a missing file")
	}
}

// buildSampleGraph builds a small graph with a public-API handler that
// touches an email field and calls into a billing helper containing a SQL
// sink, plus an unrelated internal/admin helper. This exercises file-pattern
// matching (billing, admin) and symbol-pattern matching (email, Handle) in
// one pass.
func buildSampleGraph(t *testing.T) (*graph.Graph, map[string]int) {
	t.Helper()

	dir := t.TempDir()
	apiDir := filepath.Join(dir, "internal", "api")
	billingDir := filepath.Join(dir, "internal", "billing")
	adminDir := filepath.Join(dir, "internal", "admin")
	for _, d := range []string{apiDir, billingDir, adminDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}

	apiSrc := `package api

import "net/http"

func HandleInvoice(w http.ResponseWriter, r *http.Request) {
	email := r.URL.Query().Get("email")
	_ = email
}
`
	billingSrc := `package billing

import "database/sql"

var db *sql.DB

func chargeCard(id string) {
	_, _ = db.Query("SELECT * FROM cards WHERE id = " + id)
}
`
	adminSrc := `package admin

func resetPassword(user string) {
	_ = user
}
`

	apiFile := filepath.Join(apiDir, "handler.go")
	billingFile := filepath.Join(billingDir, "billing.go")
	adminFile := filepath.Join(adminDir, "admin.go")

	for path, src := range map[string]string{
		apiFile:     apiSrc,
		billingFile: billingSrc,
		adminFile:   adminSrc,
	} {
		if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	g, err := graph.BuildFromGoFiles([]string{apiFile, billingFile, adminFile})
	if err != nil {
		t.Fatalf("BuildFromGoFiles: %v", err)
	}

	byName := make(map[string]int)
	for _, n := range g.Nodes {
		byName[n.Name] = n.ID
	}
	return g, byName
}

// TestApplyOverlay_TagsExpectedNodes builds a small graph and applies an org
// context, then asserts the specific nodes we expect got PII and boundary
// tags, using patterns authored against file paths and symbol names.
func TestApplyOverlay_TagsExpectedNodes(t *testing.T) {
	g, byName := buildSampleGraph(t)

	ctx := &OrgContext{
		App: AppInfo{Name: "test app", Description: "test"},
		SensitiveData: []SensitiveDataCategory{
			{
				Category:       "PII",
				SymbolPatterns: []string{"(?i)email"}, // won't match here (email is a local var, not the func name); see below for file-pattern coverage
			},
			{
				Category:     "payment",
				FilePatterns: []string{"internal/billing/**"},
			},
			{
				Category:       "credentials",
				SymbolPatterns: []string{"(?i)resetpassword"},
			},
		},
		TrustBoundaries: []TrustBoundary{
			{
				Name:           "public API",
				SymbolPatterns: []string{"^api\\.Handle"},
			},
			{
				Name:         "internal admin",
				FilePatterns: []string{"internal/admin/**"},
			},
		},
	}

	res := ApplyOverlay(g, ctx)
	if res.SensitiveMatches == 0 {
		t.Error("expected at least one sensitive-data match")
	}
	if res.BoundaryMatches == 0 {
		t.Error("expected at least one boundary match")
	}

	handlerID, ok := byName["api.HandleInvoice"]
	if !ok {
		t.Fatal("api.HandleInvoice node not found")
	}
	handler := g.Nodes[handlerID]
	if handler.Tags[TagBoundary] != "public API" {
		t.Errorf("HandleInvoice trust_boundary tag = %q, want %q", handler.Tags[TagBoundary], "public API")
	}

	billingID, ok := byName["billing.chargeCard"]
	if !ok {
		t.Fatal("billing.chargeCard node not found")
	}
	billingNode := g.Nodes[billingID]
	if !billingNode.PII {
		t.Error("billing.chargeCard should be marked PII (payment category, file pattern match)")
	}
	if billingNode.Tags[TagSensitiveCategory] != "payment" {
		t.Errorf("chargeCard sensitive_data_category tag = %q, want %q", billingNode.Tags[TagSensitiveCategory], "payment")
	}

	adminID, ok := byName["admin.resetPassword"]
	if !ok {
		t.Fatal("admin.resetPassword node not found")
	}
	adminNode := g.Nodes[adminID]
	if !adminNode.PII {
		t.Error("admin.resetPassword should be marked PII (credentials category, symbol pattern match)")
	}
	if adminNode.Tags[TagBoundary] != "internal admin" {
		t.Errorf("resetPassword trust_boundary tag = %q, want %q", adminNode.Tags[TagBoundary], "internal admin")
	}

	// A node with no matching pattern should be untouched: no Tags map, PII
	// left exactly as the generic heuristic set it. billing.chargeCard has no
	// PII-hinting identifier itself, but the file pattern above already
	// marked it PII/payment, so instead check a node the overlay truly never
	// touches: none exist here since every file matches some pattern, so
	// assert the negative on a boundary that has no rule at all.
	if handler.Tags[TagSensitiveCategory] != "" {
		t.Errorf("HandleInvoice should not have a sensitive_data_category tag, got %q", handler.Tags[TagSensitiveCategory])
	}
}

// TestApplyOverlay_NilSafe proves ApplyOverlay is a no-op (not a panic) on a
// nil graph or nil context.
func TestApplyOverlay_NilSafe(t *testing.T) {
	g, _ := buildSampleGraph(t)
	if res := ApplyOverlay(g, nil); res.SensitiveMatches != 0 || res.BoundaryMatches != 0 {
		t.Errorf("expected zero-value result for nil ctx, got %+v", res)
	}
	if res := ApplyOverlay(nil, &OrgContext{}); res.SensitiveMatches != 0 || res.BoundaryMatches != 0 {
		t.Errorf("expected zero-value result for nil graph, got %+v", res)
	}
}

// TestWriteScaffold_CreatesFileAndRefusesOverwrite exercises the onboarding
// scaffold: it should create .trojan/context.yaml under root, and refuse to
// clobber an existing one unless force is passed.
func TestWriteScaffold_CreatesFileAndRefusesOverwrite(t *testing.T) {
	root := t.TempDir()

	path, err := WriteScaffold(root, false)
	if err != nil {
		t.Fatalf("WriteScaffold: %v", err)
	}
	if path != Path(root) {
		t.Errorf("WriteScaffold path = %q, want %q", path, Path(root))
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read scaffold: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("scaffold file is empty")
	}

	// A second call without force should refuse to overwrite.
	if _, err := WriteScaffold(root, false); err == nil {
		t.Error("expected WriteScaffold to refuse to overwrite an existing file")
	}

	// With force it should succeed.
	if _, err := WriteScaffold(root, true); err != nil {
		t.Errorf("WriteScaffold with force: %v", err)
	}
}

// TestSave_RoundTrip proves Save writes a context that Load can read back
// with the same values, and that it returns an absolute path to the file it
// wrote at the conventional location.
func TestSave_RoundTrip(t *testing.T) {
	root := t.TempDir()

	want := &OrgContext{
		App: AppInfo{
			Name:        "Acme Billing API",
			Description: "Billing API for a B2B SaaS product.",
		},
		SensitiveData: []SensitiveDataCategory{
			{Category: "PII", Description: "Customer contact info", SymbolPatterns: []string{"(?i)email"}},
		},
		TrustBoundaries: []TrustBoundary{
			{Name: "public API", FilePatterns: []string{"internal/api/**"}},
		},
		ThreatActors: []ThreatActor{
			{Name: "external attacker", Targets: []string{"public API"}},
		},
	}

	path, err := Save(root, want)
	if err != nil {
		t.Fatalf("Save: %v", err)
	}
	if !filepath.IsAbs(path) {
		t.Errorf("Save path = %q, want an absolute path", path)
	}
	wantPath, err := filepath.Abs(Path(root))
	if err != nil {
		t.Fatalf("filepath.Abs: %v", err)
	}
	if path != wantPath {
		t.Errorf("Save path = %q, want %q", path, wantPath)
	}
	if !Exists(Path(root)) {
		t.Fatal("Save did not create a file at the conventional path")
	}

	got, err := Load(Path(root))
	if err != nil {
		t.Fatalf("Load after Save: %v", err)
	}
	if got.App.Name != want.App.Name || got.App.Description != want.App.Description {
		t.Errorf("App round-trip mismatch: got %+v, want %+v", got.App, want.App)
	}
	if len(got.SensitiveData) != 1 || got.SensitiveData[0].Category != "PII" {
		t.Errorf("SensitiveData round-trip mismatch: got %+v", got.SensitiveData)
	}
	if len(got.TrustBoundaries) != 1 || got.TrustBoundaries[0].Name != "public API" {
		t.Errorf("TrustBoundaries round-trip mismatch: got %+v", got.TrustBoundaries)
	}
	if len(got.ThreatActors) != 1 || got.ThreatActors[0].Name != "external attacker" {
		t.Errorf("ThreatActors round-trip mismatch: got %+v", got.ThreatActors)
	}

	// Save again overwrites cleanly (unlike WriteScaffold, which refuses).
	want.App.Name = "Renamed"
	if _, err := Save(root, want); err != nil {
		t.Fatalf("second Save: %v", err)
	}
	got2, err := Load(Path(root))
	if err != nil {
		t.Fatalf("Load after second Save: %v", err)
	}
	if got2.App.Name != "Renamed" {
		t.Errorf("App.Name after overwrite = %q, want %q", got2.App.Name, "Renamed")
	}
}
