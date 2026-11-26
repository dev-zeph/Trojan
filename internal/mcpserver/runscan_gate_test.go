package mcpserver

import (
	"context"
	"strings"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"

	"github.com/dev-zeph/trojan/internal/scangate"
)

func TestRunScanIsGated(t *testing.T) {
	project, _ := fixture(t)
	orig := runScanGate
	defer func() { runScanGate = orig }()

	cases := []struct {
		name string
		res  scangate.Result
		want string
	}{
		{"signed out", scangate.Result{Reason: scangate.ReasonSignedOut, Message: scangate.SignInMessage}, "Sign in to scan"},
		{"low balance", scangate.Result{Reason: scangate.ReasonLowTokens, Message: scangate.LowTokensMessage(7)}, "You have 7"},
	}
	for _, c := range cases {
		runScanGate = func() scangate.Result { return c.res }
		out, err := handleRunScan(project)(context.Background(), mcp.CallToolRequest{})
		if err != nil || !out.IsError {
			t.Fatalf("%s: expected a tool error, got %+v %v", c.name, out, err)
		}
		text, _ := out.Content[0].(mcp.TextContent)
		if !strings.Contains(text.Text, c.want) {
			t.Fatalf("%s: message %q should contain %q", c.name, text.Text, c.want)
		}
	}
}

// R3-P3-4: the signed-out wording matches the redaction build, names
// trojan login, and has no "Trojan:" prefix.
func TestRunScanGateMessage(t *testing.T) {
	cases := []struct {
		name string
		res  scangate.Result
		want string
	}{
		{"signed out", scangate.Check("", nil),
			"Sign in to scan. Every account gets 500 free tokens a month. Sign in from the Trojan desktop app, or run trojan login in a terminal, then try again."},
		{"expired", scangate.Result{Reason: scangate.ReasonSignedOut, Message: "Your sign-in has expired. " + scangate.SignInMessage},
			"Your sign-in has expired. Sign in to scan. Every account gets 500 free tokens a month. Sign in from the Trojan desktop app, or run trojan login in a terminal, then try again."},
		{"low balance", scangate.Result{Reason: scangate.ReasonLowTokens, Message: scangate.LowTokensMessage(7)}, scangate.LowTokensMessage(7)},
	}
	for _, c := range cases {
		got := runScanGateMessage(c.res)
		if got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
		if strings.HasPrefix(got, "Trojan:") || strings.ContainsRune(got, '\u2014') {
			t.Errorf("%s: prefix or em dash in %q", c.name, got)
		}
	}
}

func TestRunScanSignedOutResultNamesTrojanLogin(t *testing.T) {
	project, _ := fixture(t)
	orig := runScanGate
	defer func() { runScanGate = orig }()
	runScanGate = func() scangate.Result { return scangate.Check("", nil) }
	out, err := handleRunScan(project)(context.Background(), mcp.CallToolRequest{})
	if err != nil || !out.IsError {
		t.Fatalf("expected a tool error, got %+v %v", out, err)
	}
	text, _ := out.Content[0].(mcp.TextContent)
	if !strings.HasPrefix(text.Text, "Sign in to scan.") || !strings.Contains(text.Text, "run trojan login in a terminal") {
		t.Fatalf("message %q", text.Text)
	}
}
