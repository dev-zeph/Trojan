package mcpserver

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"

	"github.com/dev-zeph/trojan/internal/normalizer"
)

const wantSignIn = "Sign in to scan. Every account gets 500 free tokens a month. Sign in from the Trojan desktop app, or run trojan login in a terminal, then try again."

// R4-P3-2: the desktop's local MCP says exactly what run_scan says.
func TestLocalSignInMessageMatchesRunScan(t *testing.T) {
	if localSignInMessage != wantSignIn {
		t.Fatalf("got %q", localSignInMessage)
	}
	t.Setenv("HOME", t.TempDir())
	t.Setenv("USERPROFILE", t.TempDir())
	called := false
	h := requireSignIn(func(context.Context, mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		called = true
		return mcp.NewToolResultText("ran"), nil
	})
	res, err := h(context.Background(), mcp.CallToolRequest{})
	if err != nil || res == nil || !res.IsError || called {
		t.Fatalf("expected a refusal, got %+v %v called=%v", res, err, called)
	}
	if text := res.Content[0].(mcp.TextContent).Text; text != wantSignIn {
		t.Errorf("refusal %q", text)
	}
}

func TestScanFinishedMessage(t *testing.T) {
	got := scanFinishedMessage(12, 9)
	if got != "Scan finished: 12 findings (9 open)." || strings.ContainsRune(got, '\u2014') {
		t.Errorf("got %q", got)
	}
}

// R4-P3-3: get_findings and security_summary name the folder, not its path.
func TestProjectLabel(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "leaky-app")
	cases := map[string]string{
		"":                    "",
		dir:                   "leaky-app",
		dir + "/":             "leaky-app",
		"/Users/someone/shop": "shop",
		"/":                   ".",
	}
	for in, want := range cases {
		if got := projectLabel(in); got != want {
			t.Errorf("projectLabel(%q) = %q, want %q", in, got, want)
		}
	}
}

// No absolute or home path in get_findings or security_summary, even for a
// scan saved by an older build with absolute file paths.
func TestFindingsListsShowNoAbsolutePaths(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "leaky-app")
	writeScan(t, dir, []normalizer.Finding{
		{ID: "f1", Title: "Leaked Stripe access token", Scanner: "gitleaks", Severity: normalizer.SeverityCritical,
			FilePath: filepath.Join(dir, "src", "config.ts"), LineNumber: 3, Status: normalizer.StatusOpen},
		{ID: "syft-0", Title: "SBOM: 2 packages inventoried", Scanner: "syft", Severity: normalizer.SeverityInfo, FilePath: dir, Status: normalizer.StatusOpen},
	})
	project := func(context.Context, mcp.CallToolRequest) (string, error) { return dir, nil }
	for name, h := range map[string]func(projectFunc) server.ToolHandlerFunc{
		"get_findings":     handleGetFindings,
		"security_summary": handleSecuritySummary,
	} {
		res, err := h(project)(context.Background(), mcp.CallToolRequest{})
		if err != nil || res.IsError {
			t.Fatalf("%s: %v %+v", name, err, res)
		}
		text := res.Content[0].(mcp.TextContent).Text
		if strings.Contains(text, filepath.Dir(dir)) || !strings.Contains(text, `"project": "leaky-app"`) || !strings.Contains(text, "src/config.ts:3") {
			t.Errorf("%s shows an absolute path or the wrong project:\n%s", name, text)
		}
	}
}
