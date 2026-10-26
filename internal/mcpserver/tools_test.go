package mcpserver

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"

	"github.com/dev-zeph/trojan/internal/normalizer"
)

// fixture: a signed-in HOME with one scanned project.
func fixture(t *testing.T) (projectFunc, string) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	os.MkdirAll(filepath.Join(home, ".trojan"), 0700)                                                                   //nolint:errcheck
	os.WriteFile(filepath.Join(home, ".trojan", "config.json"), []byte(`{"access_token":"tok","familiarity":0}`), 0600) //nolint:errcheck
	proj := filepath.Join(home, "app")
	_, err := normalizer.SaveScanResult(proj, []normalizer.Finding{
		{ID: "c1", Severity: normalizer.SeverityCritical, Title: "Hard-coded password", FilePath: "lib/seed.ts", LineNumber: 31, Status: normalizer.StatusOpen, Verdict: "confirmed"},
		{ID: "h1", Severity: normalizer.SeverityHigh, Title: "SQL injection", FilePath: "api/q.ts", LineNumber: 9, Status: normalizer.StatusOpen, Verdict: "likely_fp"},
		{ID: "l1", Severity: normalizer.SeverityLow, Title: "Missing header", Status: normalizer.StatusOpen},
		{ID: "r1", Severity: normalizer.SeverityCritical, Title: "Old issue", Status: normalizer.StatusResolved},
	})
	if err != nil {
		t.Fatal(err)
	}
	return func(context.Context, mcp.CallToolRequest) (string, error) { return proj, nil }, proj
}

func TestGetFindingsFilters(t *testing.T) {
	project, _ := fixture(t)
	count := func(args map[string]any) int {
		text, isErr := callTool(t, handleGetFindings(project), args)
		if isErr {
			t.Fatal(text)
		}
		var out struct{ Shown int }
		json.Unmarshal([]byte(text), &out) //nolint:errcheck
		return out.Shown
	}
	if n := count(nil); n != 3 {
		t.Errorf("default (open) = %d, want 3", n)
	}
	if n := count(map[string]any{"status": "all"}); n != 4 {
		t.Errorf("all = %d, want 4", n)
	}
	if n := count(map[string]any{"min_severity": "high"}); n != 2 {
		t.Errorf("high+ = %d, want 2", n)
	}
	if n := count(map[string]any{"confirmed_only": true}); n != 1 {
		t.Errorf("confirmed = %d, want 1", n)
	}
}

func TestProjectContextRoundTrip(t *testing.T) {
	project, proj := fixture(t)
	if text, _ := callTool(t, handleGetProjectContext(project), nil); !strings.Contains(text, "no Trojan context yet") {
		t.Errorf("empty context: %s", text)
	}
	ctxArg := map[string]any{
		"app":            map[string]any{"name": "LFC Halifax", "description": "Club site with a member dashboard"},
		"sensitive_data": []any{map[string]any{"category": "PII", "file_patterns": []any{"lib/members/**"}}},
	}
	if text, isErr := callTool(t, handleUpdateProjectContext(project), map[string]any{"context": ctxArg}); isErr {
		t.Fatal(text)
	}
	if _, err := os.Stat(filepath.Join(proj, ".trojan", "context.yaml")); err != nil {
		t.Fatal("context.yaml not written")
	}
	if text, _ := callTool(t, handleGetProjectContext(project), nil); !strings.Contains(text, "LFC Halifax") || !strings.Contains(text, "lib/members/**") {
		t.Errorf("read back: %s", text)
	}
	if _, isErr := callTool(t, handleUpdateProjectContext(project), map[string]any{"context": map[string]any{"app": map[string]any{}}}); !isErr {
		t.Error("expected an error for an empty app")
	}
}

func TestSecuritySummary(t *testing.T) {
	project, _ := fixture(t)
	text, isErr := callTool(t, handleSecuritySummary(project), nil)
	if isErr || !strings.Contains(text, "Hard-coded password") || strings.Contains(text, "Old issue") || !strings.Contains(text, `"exists": false`) {
		t.Errorf("summary = %s", text)
	}
}

func TestStartWebsiteTestNeedsOwnerConfirmation(t *testing.T) {
	fixture(t)
	text, isErr := callTool(t, handleStartWebsiteTest, map[string]any{"url": "203.0.113.9"})
	if !isErr || !strings.Contains(text, "owner_confirmed") {
		t.Errorf("unconfirmed public site: %v %s", isErr, text)
	}
}

func TestNormalizeSiteURL(t *testing.T) {
	for in, want := range map[string]string{
		"localhost:3000":        "http://localhost:3000",
		"myapp.com":             "https://myapp.com",
		"https://myapp.com/x":   "https://myapp.com/x",
		"127.0.0.1:8080/health": "http://127.0.0.1:8080/health",
	} {
		if got := normalizeSiteURL(in); got != want {
			t.Errorf("normalizeSiteURL(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestGenerateSecurityReport(t *testing.T) {
	project, proj := fixture(t)
	var gotPayload map[string]any
	stub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/threat-lab" || r.Header.Get("Authorization") != "Bearer tok" {
			http.Error(w, "bad request", 400)
			return
		}
		var body struct{ Encoded string }
		json.NewDecoder(r.Body).Decode(&body) //nolint:errcheck
		inner, _ := base64.StdEncoding.DecodeString(body.Encoded)
		json.Unmarshal(inner, &gotPayload)                                                                                                                                                                                                                        //nolint:errcheck
		w.Write([]byte(`{"threat_index":35,"grade":"C","verdict":"Fix the password first.","key_risks":["Anyone can log in"],"priority_fixes":[{"rank":1,"title":"Remove hard-coded passwords","description":"Use real auth","file":"lib/seed.ts","line":31}]}`)) //nolint:errcheck
	}))
	defer stub.Close()
	old := edgeBase
	edgeBase = stub.URL + "/"
	defer func() { edgeBase = old }()

	text, isErr := callTool(t, handleGenerateReport(project), map[string]any{"kind": "security"})
	if isErr {
		t.Fatal(text)
	}
	if gotPayload["user_familiarity"] != float64(0) || len(gotPayload["findings"].([]any)) != 4 {
		t.Errorf("payload = %v", gotPayload)
	}
	files, _ := filepath.Glob(filepath.Join(proj, ".trojan", "reports", "security-*.html"))
	if len(files) != 1 {
		t.Fatalf("html report not written: %v", files)
	}
	html, _ := os.ReadFile(files[0])
	for _, want := range []string{"Grade C · 65/100", "Anyone can log in", "Remove hard-coded passwords (lib/seed.ts:31)"} {
		if !strings.Contains(string(html), want) {
			t.Errorf("report missing %q", want)
		}
	}
}

func TestReportOutOfCredits(t *testing.T) {
	project, _ := fixture(t)
	stub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusPaymentRequired) }))
	defer stub.Close()
	old := edgeBase
	edgeBase = stub.URL + "/"
	defer func() { edgeBase = old }()
	if text, isErr := callTool(t, handleGenerateReport(project), map[string]any{"kind": "compliance"}); !isErr || !strings.Contains(text, "credits") {
		t.Errorf("402: %v %s", isErr, text)
	}
}

func TestRelPath(t *testing.T) {
	if relPath("/p", "/p/src/a.ts") != "src/a.ts" || relPath("/p", "src/./a.ts") != "src/a.ts" {
		t.Error("relPath mismatch")
	}
}
