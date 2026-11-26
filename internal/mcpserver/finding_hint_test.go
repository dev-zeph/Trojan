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

func TestAddSignInHint(t *testing.T) {
	fc := findingContext{}
	addSignInHint(&fc, false)
	if fc.Explanation != signInHint {
		t.Errorf("signed out, no explanation: got %q", fc.Explanation)
	}
	fc = findingContext{}
	addSignInHint(&fc, true)
	if fc.Explanation != "" {
		t.Errorf("signed in: got %q", fc.Explanation)
	}
	fc = findingContext{Simply: "Already explained."}
	addSignInHint(&fc, false)
	if fc.Explanation != "" {
		t.Errorf("has explanation: got %q", fc.Explanation)
	}
}

func writeScan(t *testing.T, dir string, findings []normalizer.Finding) {
	t.Helper()
	scans := filepath.Join(dir, ".trojan", "scans")
	if err := os.MkdirAll(scans, 0o755); err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(normalizer.ScanResult{ProjectPath: dir, Findings: findings})
	if err := os.WriteFile(filepath.Join(scans, "2026-11-26.json"), data, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestGetFindingSignedOutHint(t *testing.T) {
	dir := t.TempDir()
	writeScan(t, dir, []normalizer.Finding{
		{ID: "f1", Title: "Leaked Stripe Access Token", Scanner: "gitleaks", FilePath: "a.env", Status: normalizer.StatusOpen},
		{ID: "f2", Title: "XSS", Scanner: "semgrep", FilePath: "a.js", Simply: "Explained.", Status: normalizer.StatusOpen},
	})
	project := func(context.Context, mcp.CallToolRequest) (string, error) { return dir, nil }
	orig := isSignedIn
	defer func() { isSignedIn = orig }()

	for _, c := range []struct {
		signedIn bool
		id       string
		want     bool
	}{{false, "f1", true}, {true, "f1", false}, {false, "f2", false}} {
		isSignedIn = func() bool { return c.signedIn }
		req := mcp.CallToolRequest{}
		req.Params.Arguments = map[string]any{"id": c.id}
		res, err := handleGetFindingWithContext(project)(context.Background(), req)
		if err != nil || res.IsError {
			t.Fatalf("get_finding %s: %v %+v", c.id, err, res)
		}
		text := res.Content[0].(mcp.TextContent).Text
		if got := strings.Contains(text, `"explanation": "`+signInHint+`"`); got != c.want {
			t.Errorf("signedIn=%v id=%s: hint present=%v, want %v\n%s", c.signedIn, c.id, got, c.want, text)
		}
	}
}

func TestNoScanResultsMessage(t *testing.T) {
	for _, setup := range []func(string){
		func(string) {},
		func(d string) { os.MkdirAll(filepath.Join(d, ".trojan", "scans"), 0o755) }, //nolint:errcheck
	} {
		dir := t.TempDir()
		setup(dir)
		_, err := loadLatestScan(dir)
		if err == nil {
			t.Fatal("expected an error")
		}
		msg := err.Error()
		if msg != noScanResultsMsg {
			t.Errorf("got %q", msg)
		}
		if strings.ContainsRune(msg, '\u2014') || strings.Contains(msg, dir) {
			t.Errorf("message has an em dash or the folder path: %q", msg)
		}
	}
}
