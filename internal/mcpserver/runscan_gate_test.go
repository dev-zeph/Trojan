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
