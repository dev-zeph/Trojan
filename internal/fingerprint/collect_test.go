package fingerprint

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func has(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

func TestCollect_Vibeapp(t *testing.T) {
	fp, err := Collect(filepath.Join("..", "testdata", "vibeapp"))
	if err != nil {
		t.Fatal(err)
	}
	if fp.Framework != "nextjs" {
		t.Errorf("framework = %q, want nextjs", fp.Framework)
	}
	for _, tbl := range []string{"orders", "profiles", "posts", "invoices"} {
		if !has(fp.DataStores, tbl) {
			t.Errorf("data stores %v missing %s", fp.DataStores, tbl)
		}
	}
	for _, env := range []string{"NEXT_PUBLIC_SUPABASE_URL", "NEXT_PUBLIC_SUPABASE_ANON_KEY", "SUPABASE_SERVICE_ROLE_KEY", "STRIPE_SECRET_KEY", "DATABASE_URL"} {
		if !has(fp.EnvVarNames, env) {
			t.Errorf("env names %v missing %s", fp.EnvVarNames, env)
		}
	}
	if !has(fp.ThirdParty, "supabase") || !has(fp.ThirdParty, "stripe") {
		t.Errorf("third party = %v, want supabase and stripe", fp.ThirdParty)
	}
	found := false
	for _, r := range fp.Routes {
		if r.Method == "POST" && r.Path == "/api/orders" {
			found = true
		}
	}
	if !found {
		t.Errorf("routes %+v missing POST /api/orders", fp.Routes)
	}
	if !has(fp.Languages, "typescript") {
		t.Errorf("languages = %v", fp.Languages)
	}
}

func TestCollect_CanaryNeverLeaks(t *testing.T) {
	const canary = "TROJAN_CANARY_DO_NOT_LEAK_7731"
	raw, err := os.ReadFile(filepath.Join("..", "testdata", "vibeapp", ".env"))
	if err != nil || !strings.Contains(string(raw), canary) {
		t.Fatalf("fixture .env must contain the canary (err=%v)", err)
	}
	fp, err := Collect(filepath.Join("..", "testdata", "vibeapp"))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(fp)
	if strings.Contains(string(b), canary) {
		t.Fatal("canary leaked into serialized fingerprint")
	}
}

func TestCollect_Express(t *testing.T) {
	fp, err := Collect(filepath.Join("..", "testdata", "expressapp"))
	if err != nil {
		t.Fatal(err)
	}
	if fp.Framework != "express" {
		t.Errorf("framework = %q, want express", fp.Framework)
	}
	if !has(fp.ThirdParty, "supabase") {
		t.Errorf("third party = %v", fp.ThirdParty)
	}
}

func TestCollect_Pyapp(t *testing.T) {
	fp, err := Collect(filepath.Join("..", "testdata", "pyapp"))
	if err != nil {
		t.Fatal(err)
	}
	if fp.Framework != "fastapi" && fp.Framework != "flask" {
		t.Errorf("framework = %q, want fastapi or flask", fp.Framework)
	}
	if !has(fp.Languages, "python") {
		t.Errorf("languages = %v", fp.Languages)
	}
	if !has(fp.AuthLibraries, "flask-login") {
		t.Errorf("auth libs = %v", fp.AuthLibraries)
	}
}

func TestCollect_NotADirectory(t *testing.T) {
	if _, err := Collect(filepath.Join(t.TempDir(), "nope")); err == nil {
		t.Fatal("expected error")
	}
}

func TestEnvNames_NamesOnly(t *testing.T) {
	got := envNames("# c\nA=secret1\nexport B = secret2\nC=\n  bad line\n")
	if strings.Join(got, ",") != "A,B,C" {
		t.Fatalf("got %v", got)
	}
}

func TestTablesAndModels(t *testing.T) {
	if got := tablesFromSQL(`CREATE TABLE IF NOT EXISTS public."Users" (id int); create table orders ();`); strings.Join(got, ",") != "users,orders" {
		t.Errorf("sql: %v", got)
	}
	if got := modelsFromPrisma("model User {\n id Int\n}\nmodel Post {\n}"); strings.Join(got, ",") != "User,Post" {
		t.Errorf("prisma: %v", got)
	}
	py := "class Item(db.Model):\n    __tablename__ = 'items'\n"
	if got := tablesFromPython(py); !has(got, "items") || !has(got, "Item") {
		t.Errorf("python: %v", got)
	}
}

func TestFit_TrimsToCap(t *testing.T) {
	var fp Fingerprint
	for i := 0; i < 2000; i++ {
		fp.Dependencies = append(fp.Dependencies, strings.Repeat("dep", 10))
		fp.Routes = append(fp.Routes, RouteSummary{Method: "GET", Path: "/some/long/path/" + strings.Repeat("x", 30), File: "a/b/c.ts"})
	}
	out := fit(fp)
	b, _ := json.Marshal(out)
	if len(b) > MaxPayloadBytes {
		t.Fatalf("size %d over cap", len(b))
	}
}

// The Trojan repo itself is the largest realistic input we have.
func TestCollect_TrojanRepoUnderCap(t *testing.T) {
	root := filepath.Join("..", "..")
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Skip("repo root not found")
	}
	fp, err := Collect(root)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(fp)
	t.Logf("trojan repo fingerprint: %d bytes, framework=%q routes=%d deps=%d outline=%d", len(b), fp.Framework, len(fp.Routes), len(fp.Dependencies), len(fp.Outline))
	if len(b) > MaxPayloadBytes {
		t.Fatalf("fingerprint %d bytes exceeds cap %d", len(b), MaxPayloadBytes)
	}
}
