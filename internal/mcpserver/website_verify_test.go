package mcpserver

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"

	"github.com/dev-zeph/trojan/internal/memory"
	"github.com/dev-zeph/trojan/internal/normalizer"
)

// verify_fix on a website finding replays its proof: a now-secured endpoint is
// reported fixed, marked resolved in website storage, and recorded in memory;
// a still-vulnerable one stays open.
func TestVerifyFixRoutesWebsiteFindings(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/admin": // fixed: now requires login
			w.WriteHeader(http.StatusUnauthorized)
		default: // still vulnerable
			w.WriteHeader(200)
			_, _ = w.Write([]byte("open data"))
		}
	}))
	defer srv.Close()

	status := normalizer.ProofSignal{Kind: normalizer.SignalStatus}
	if _, err := normalizer.SaveWebsiteTest(srv.URL, []normalizer.Finding{
		{ID: "agentic-aaaaaaaaaaaa", Title: "Unauth admin", RuleID: "agentic", FilePath: srv.URL + "/admin", Status: normalizer.StatusOpen,
			Proof: &normalizer.Proof{Method: "GET", URL: srv.URL + "/admin", OrigStatus: 200, Signal: status}},
		{ID: "agentic-bbbbbbbbbbbb", Title: "Unauth export", RuleID: "agentic", FilePath: srv.URL + "/export", Status: normalizer.StatusOpen,
			Proof: &normalizer.Proof{Method: "GET", URL: srv.URL + "/export", OrigStatus: 200, Signal: status}},
		{ID: "nuclei-0", Title: "Old nuclei", Scanner: "nuclei", Status: normalizer.StatusOpen},
	}); err != nil {
		t.Fatal(err)
	}

	noProject := func(context.Context, mcp.CallToolRequest) (string, error) { return "", context.Canceled }

	text, isErr := callTool(t, handleVerifyFix(noProject), map[string]any{"id": "agentic-aaaaaaaaaaaa"})
	if isErr || !strings.Contains(text, "VERIFIED FIXED") {
		t.Fatalf("verify_fix(fixed) = %s", text)
	}
	text, isErr = callTool(t, handleVerifyFix(noProject), map[string]any{"id": "agentic-bbbbbbbbbbbb"})
	if isErr || !strings.Contains(text, "NOT FIXED") {
		t.Fatalf("verify_fix(still vulnerable) = %s", text)
	}
	text, _ = callTool(t, handleVerifyFix(noProject), map[string]any{"id": "nuclei-0"})
	if !strings.Contains(text, "INCONCLUSIVE") {
		t.Fatalf("verify_fix(no proof) = %s", text)
	}

	siteDir, _, ok := findWebsiteFinding("agentic-aaaaaaaaaaaa")
	if !ok {
		t.Fatal("website finding vanished")
	}
	scan, err := loadLatestScan(siteDir)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]normalizer.Status{}
	for _, f := range scan.Findings {
		got[f.ID] = f.Status
	}
	if got["agentic-aaaaaaaaaaaa"] != normalizer.StatusResolved || got["agentic-bbbbbbbbbbbb"] != normalizer.StatusOpen || got["nuclei-0"] != normalizer.StatusOpen {
		t.Errorf("statuses after retest = %v", got)
	}

	store, err := memory.Open(siteDir)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	events, _ := store.All()
	fixed := 0
	for _, e := range events {
		if e.Kind == memory.KindFixed && e.Title == "Unauth admin" {
			fixed++
		}
	}
	if fixed != 1 || len(events) != 1 {
		t.Errorf("memory events = %+v, want one fixed event for Unauth admin", events)
	}
}

// A code finding ID is not routed to the website retest: it goes to the
// existing code path (which needs a project).
func TestVerifyFixCodeIDUsesCodePath(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	noProject := func(context.Context, mcp.CallToolRequest) (string, error) {
		return "", errNoProjectForTest
	}
	text, isErr := callTool(t, handleVerifyFix(noProject), map[string]any{"id": "semgrep-123"})
	if !isErr || !strings.Contains(text, errNoProjectForTest.Error()) {
		t.Fatalf("code id should take the project path, got %q", text)
	}
}

type testErr string

func (e testErr) Error() string { return string(e) }

const errNoProjectForTest = testErr("no project for test")

// retest_website_findings with no ids re-checks every open finding of the site.
func TestRetestWebsiteFindingsAll(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("[escaped]"))
	}))
	defer srv.Close()
	refl := normalizer.ProofSignal{Kind: normalizer.SignalReflection, Marker: "markerXYZ123"}
	normalizer.SaveWebsiteTest(srv.URL, []normalizer.Finding{ //nolint:errcheck
		{ID: "agentic-cccccccccccc", Title: "XSS", Status: normalizer.StatusOpen,
			Proof: &normalizer.Proof{Method: "GET", URL: srv.URL + "/s?q=markerXYZ123", OrigStatus: 200, Signal: refl}},
		{ID: "agentic-dddddddddddd", Title: "old", Status: normalizer.StatusResolved},
	})

	text, isErr := callTool(t, handleRetestWebsiteFindings, map[string]any{"url": srv.URL})
	if isErr {
		t.Fatal(text)
	}
	var out struct {
		Retested, Fixed int
	}
	json.Unmarshal([]byte(text), &out) //nolint:errcheck
	if out.Retested != 1 || out.Fixed != 1 {
		t.Errorf("retest summary = %s", text)
	}
}

// get_all_findings returns code and website findings with distinct sources.
func TestGetAllFindingsUnified(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	root := t.TempDir()
	normalizer.SaveScanResult(root, []normalizer.Finding{ //nolint:errcheck
		{ID: "code1", Severity: normalizer.SeverityHigh, Title: "SQLi", FilePath: "a.go", LineNumber: 3, Status: normalizer.StatusOpen},
	})
	normalizer.SaveWebsiteTest("https://shop.example.com", []normalizer.Finding{ //nolint:errcheck
		{ID: "agentic-eeeeeeeeeeee", Severity: normalizer.SeverityHigh, Title: "IDOR", FilePath: "https://shop.example.com/api/orders/2", Status: normalizer.StatusOpen},
	})
	project := func(context.Context, mcp.CallToolRequest) (string, error) { return root, nil }

	text, isErr := callTool(t, handleGetAllFindings(project), nil)
	if isErr {
		t.Fatal(text)
	}
	var out struct {
		Findings []struct{ ID, Source string }
	}
	json.Unmarshal([]byte(text), &out) //nolint:errcheck
	src := map[string]string{}
	for _, f := range out.Findings {
		src[f.ID] = f.Source
	}
	if src["code1"] != "code" || src["agentic-eeeeeeeeeeee"] != "website" || len(src) != 2 {
		t.Errorf("unified findings = %s", text)
	}
}
