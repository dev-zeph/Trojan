package mcpserver

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"

	"github.com/dev-zeph/trojan/internal/normalizer"
)

func TestDisplayPath(t *testing.T) {
	proj := filepath.Join(t.TempDir(), "shop")
	cases := []struct{ in, want string }{
		{"", ""},
		{"src/a.ts", "src/a.ts"},
		{".", "."},
		{proj, "."},
		{proj + "/", "."},
		{filepath.Join(proj, "src", "a.ts"), "src/a.ts"},
		{"/Users/someone/elsewhere/secret.env", "secret.env"},
		{filepath.Join(filepath.Dir(proj), "shop2", "x.go"), "x.go"},
	}
	for _, c := range cases {
		if got := displayPath(proj, c.in); got != c.want {
			t.Errorf("displayPath(%q) = %q, want %q", c.in, got, c.want)
		}
	}
	if got := displayPath("", "/abs/file.txt"); got != "file.txt" {
		t.Errorf("no project: got %q", got)
	}
}

// R3-P3-5: an SBOM item saved with an absolute path (older builds) is shown
// as "." and gets no sign-in hint, since it has nothing to explain.
func TestSBOMItemIsRelativeAndHasNoHint(t *testing.T) {
	dir := t.TempDir()
	writeScan(t, dir, []normalizer.Finding{
		{ID: "syft-0", Title: "SBOM: 2 packages inventoried", Scanner: "syft", Severity: normalizer.SeverityInfo, FilePath: dir, Status: normalizer.StatusOpen},
	})
	project := func(context.Context, mcp.CallToolRequest) (string, error) { return dir, nil }
	orig := isSignedIn
	defer func() { isSignedIn = orig }()
	isSignedIn = func() bool { return false }

	req := mcp.CallToolRequest{}
	req.Params.Arguments = map[string]any{"id": "syft-0"}
	res, err := handleGetFindingWithContext(project)(context.Background(), req)
	if err != nil || res.IsError {
		t.Fatalf("get_finding: %v %+v", err, res)
	}
	text := res.Content[0].(mcp.TextContent).Text
	if strings.Contains(text, dir) || !strings.Contains(text, `"file_path": "."`) {
		t.Errorf("absolute path shown or not \".\":\n%s", text)
	}
	if strings.Contains(text, signInHint) {
		t.Errorf("info-only item got the sign-in hint:\n%s", text)
	}

	list, err := handleGetFindings(project)(context.Background(), mcp.CallToolRequest{Params: mcp.CallToolParams{Arguments: map[string]any{"severity": "info"}}})
	if err != nil || list.IsError {
		t.Fatalf("get_findings: %v %+v", err, list)
	}
	if lt := list.Content[0].(mcp.TextContent).Text; !strings.Contains(lt, `"location": "."`) || strings.Contains(lt, `"location": "`+dir) {
		t.Errorf("get_findings location is not \".\":\n%s", lt)
	}
}

func TestAddSignInHintSkipsInfoOnly(t *testing.T) {
	fc := findingContext{Severity: string(normalizer.SeverityInfo)}
	addSignInHint(&fc, false)
	if fc.Explanation != "" {
		t.Errorf("info-only item got %q", fc.Explanation)
	}
	fc = findingContext{Severity: string(normalizer.SeverityHigh)}
	addSignInHint(&fc, false)
	if fc.Explanation != signInHint {
		t.Errorf("high item: got %q", fc.Explanation)
	}
}
