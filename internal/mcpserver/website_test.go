package mcpserver

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"

	"github.com/dev-zeph/trojan/internal/normalizer"
)

func callTool(t *testing.T, h func(context.Context, mcp.CallToolRequest) (*mcp.CallToolResult, error), args map[string]any) (string, bool) {
	t.Helper()
	req := mcp.CallToolRequest{}
	req.Params.Arguments = args
	res, err := h(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	return res.Content[0].(mcp.TextContent).Text, res.IsError
}

func TestWebsiteFindingsRoundTrip(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	if _, isErr := callTool(t, handleGetWebsiteFindings, nil); !isErr {
		t.Error("expected an error before any website test")
	}

	normalizer.SaveWebsiteTest("https://shop.example.com/login", []normalizer.Finding{{ID: "w1", Title: "IDOR on /api/orders", Status: normalizer.StatusOpen}}) //nolint:errcheck
	normalizer.SaveWebsiteTest("http://localhost:3000", []normalizer.Finding{{ID: "w2", Title: "Missing CSP", Status: normalizer.StatusOpen}})                  //nolint:errcheck

	text, isErr := callTool(t, handleListWebsiteTests, nil)
	if isErr || !strings.Contains(text, "shop.example.com") || !strings.Contains(text, "localhost:3000") {
		t.Errorf("list_website_tests = %s", text)
	}

	text, isErr = callTool(t, handleGetWebsiteFindings, map[string]any{"url": "shop.example.com"})
	if isErr || !strings.Contains(text, "IDOR on /api/orders") {
		t.Errorf("get_website_findings(shop) = %s", text)
	}
	text, isErr = callTool(t, handleGetWebsiteFindings, map[string]any{"url": "http://localhost:3000"})
	if isErr || !strings.Contains(text, "Missing CSP") {
		t.Errorf("get_website_findings(localhost) = %s", text)
	}
	if _, isErr = callTool(t, handleGetWebsiteFindings, map[string]any{"url": "never-tested.com"}); !isErr {
		t.Error("expected an error for an untested site")
	}

	// mark_fixed finds website findings even when the project has no scans.
	noProject := func(context.Context, mcp.CallToolRequest) (string, error) { return "", os.ErrNotExist }
	if text, isErr := callTool(t, handleUpdateStatus(noProject, normalizer.StatusResolved), map[string]any{"id": "w1"}); isErr {
		t.Fatalf("mark website finding fixed: %s", text)
	}
	text, _ = callTool(t, handleGetWebsiteFindings, map[string]any{"url": "shop.example.com"})
	var got struct{ Findings []normalizer.Finding }
	json.Unmarshal([]byte(text), &got) //nolint:errcheck
	if len(got.Findings) != 1 || got.Findings[0].Status != normalizer.StatusResolved {
		t.Errorf("status not saved: %s", text)
	}
}

func TestImportDesktopCache(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	cache := filepath.Join(home, ".trojan", "desktop-cache")
	os.MkdirAll(cache, 0755) //nolint:errcheck
	write := func(name string, scan normalizer.ScanResult) {
		data, _ := json.Marshal(scan)
		os.WriteFile(filepath.Join(cache, name), data, 0644) //nolint:errcheck
	}
	write("a.json", normalizer.ScanResult{ProjectPath: "https://old.example.com", Findings: []normalizer.Finding{{ID: "x"}}})
	write("b.json", normalizer.ScanResult{ProjectPath: "/Users/me/code-project", Findings: []normalizer.Finding{{ID: "y"}}})

	importDesktopCache()
	dirs := normalizer.WebsiteSiteDirs()
	if len(dirs) != 1 || filepath.Base(dirs[0]) != "old.example.com" {
		t.Fatalf("imported sites = %v", dirs)
	}
	importDesktopCache() // second run must not add another copy
	files, _ := filepath.Glob(filepath.Join(dirs[0], ".trojan", "scans", "*.json"))
	if len(files) != 1 {
		t.Errorf("re-import duplicated results: %v", files)
	}
}
