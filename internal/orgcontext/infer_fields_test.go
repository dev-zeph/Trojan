package orgcontext

import (
	"os"
	"path/filepath"
	"testing"
)

// TestSave_RoundTrip_InferredFields proves the inferred fields (data stores,
// auth model, third-party services, learned facts) survive Save then Load.
func TestSave_RoundTrip_InferredFields(t *testing.T) {
	root := t.TempDir()
	want := &OrgContext{
		App:                AppInfo{Name: "Shop", Description: "A small shop."},
		DataStores:         []string{"orders", "profiles"},
		AuthModel:          &AuthModel{WhoLogsIn: "customers and staff", Roles: []string{"customer", "admin"}, AdminArea: true},
		ThirdPartyServices: []string{"stripe", "supabase"},
		Learned:            []LearnedFact{{Fact: "orders is writable without login", Evidence: "POST /api/orders", Source: "scan"}},
	}
	if _, err := Save(root, want); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := Load(Path(root))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(got.DataStores) != 2 || got.DataStores[1] != "profiles" {
		t.Errorf("DataStores = %v", got.DataStores)
	}
	if got.AuthModel == nil || got.AuthModel.WhoLogsIn != "customers and staff" || !got.AuthModel.AdminArea || len(got.AuthModel.Roles) != 2 {
		t.Errorf("AuthModel = %+v", got.AuthModel)
	}
	if len(got.ThirdPartyServices) != 2 || got.ThirdPartyServices[0] != "stripe" {
		t.Errorf("ThirdPartyServices = %v", got.ThirdPartyServices)
	}
	if len(got.Learned) != 1 || got.Learned[0].Source != "scan" || got.Learned[0].Evidence != "POST /api/orders" {
		t.Errorf("Learned = %+v", got.Learned)
	}
}

// TestLoad_OldStyleContextHasNoNewFields proves a context.yaml written before
// the inferred fields existed still loads, with the new fields zero-valued.
func TestLoad_OldStyleContextHasNoNewFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "context.yaml")
	if err := os.WriteFile(path, []byte(sampleYAML), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got.App.Name != "Acme Billing API" || len(got.SensitiveData) == 0 {
		t.Errorf("old fields not loaded: %+v", got)
	}
	if got.DataStores != nil || got.AuthModel != nil || got.ThirdPartyServices != nil || got.Learned != nil {
		t.Errorf("new fields should be empty: %+v", got)
	}
}
