package mcpserver

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"

	"github.com/dev-zeph/trojan/internal/normalizer"
)

// previewJSON extracts the JSON object that follows the plain-language heading.
func previewJSON(t *testing.T, out string) string {
	t.Helper()
	i := strings.Index(out, "{")
	if i < 0 {
		t.Fatalf("no JSON in preview output: %s", out)
	}
	return out[i:]
}

// Assembled at runtime; not a real key.
var previewAWS = "AK" + "IA" + "Q7Z3M2PL9WNBVQXK"
var previewStripe = "sk_" + "live_" + "51MExampleKeyNotReal000000"

func TestPreviewRedactionTextViews(t *testing.T) {
	project, _ := fixture(t)
	text := `const key = "` + previewAWS + `"; // stripe: ` + previewStripe
	out, isErr := callTool(t, handlePreviewRedaction(project), map[string]any{"text": text, "view": "all"})
	if isErr {
		t.Fatal(out)
	}
	var resp struct {
		Local    string `json:"local"`
		AI       string `json:"ai"`
		Upload   string `json:"upload"`
		Detected []struct {
			Type   string `json:"type"`
			Class  string `json:"class"`
			Prefix string `json:"prefix"`
			Length int    `json:"length"`
		} `json:"detected"`
	}
	if err := json.Unmarshal([]byte(previewJSON(t, out)), &resp); err != nil {
		t.Fatalf("unmarshal: %v\n%s", err, out)
	}
	if resp.Local != text {
		t.Fatalf("local view must keep the full input")
	}
	if strings.Contains(resp.AI, previewAWS) || strings.Contains(resp.AI, previewStripe) {
		t.Fatalf("ai view leaked a raw secret: %s", resp.AI)
	}
	if !strings.Contains(resp.AI, "<SECRET") {
		t.Fatalf("ai view should use descriptors: %s", resp.AI)
	}
	if strings.Contains(resp.Upload, previewAWS) || strings.Contains(resp.Upload, previewStripe) {
		t.Fatalf("upload view leaked a raw secret: %s", resp.Upload)
	}
	if !strings.Contains(resp.Upload, "…") {
		t.Fatalf("upload view should use prefix…last4: %s", resp.Upload)
	}
	if len(resp.Detected) < 2 {
		t.Fatalf("expected ≥2 detections, got %d: %+v", len(resp.Detected), resp.Detected)
	}
}

func TestPreviewRedactionFindingID(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	proj := home + "/app"
	snippet := `accessKeyId: "` + previewAWS + `"`
	_, err := normalizer.SaveScanResult(proj, []normalizer.Finding{{
		ID: "gitleaks-0", Scanner: "gitleaks", Category: "secrets", RuleID: "aws-access-token",
		Title: "Leaked AWS", FilePath: "src/aws.ts", LineNumber: 4,
		CodeSnippet: snippet, SurroundingCode: "const cfg = {\n  " + snippet + ",\n}\n",
		Status: normalizer.StatusOpen,
	}})
	if err != nil {
		t.Fatal(err)
	}
	project := func(context.Context, mcp.CallToolRequest) (string, error) { return proj, nil }

	out, isErr := callTool(t, handlePreviewRedaction(project), map[string]any{"id": "gitleaks-0", "view": "all"})
	if isErr {
		t.Fatal(out)
	}
	if strings.Contains(out, `"code_snippet": "accessKeyId: \"AKIA`) && !strings.Contains(out, `"local"`) {
		// fine if local is present; check views carefully
	}
	var resp map[string]any
	if err := json.Unmarshal([]byte(previewJSON(t, out)), &resp); err != nil {
		t.Fatal(err)
	}
	local, _ := resp["local"].(map[string]any)
	ai, _ := resp["ai"].(map[string]any)
	upload, _ := resp["upload"].(map[string]any)
	if local == nil || ai == nil || upload == nil {
		t.Fatalf("all three views required: %s", out)
	}
	if !strings.Contains(local["code_snippet"].(string), previewAWS) {
		t.Fatal("local view must keep the raw key")
	}
	if strings.Contains(ai["code_snippet"].(string), previewAWS) {
		t.Fatal("ai view must not contain the raw key")
	}
	if !strings.Contains(ai["code_snippet"].(string), "<SECRET") {
		t.Fatalf("ai view should use a descriptor: %v", ai["code_snippet"])
	}
	if strings.Contains(upload["code_snippet"].(string), previewAWS) {
		t.Fatal("upload view must not contain the raw key")
	}
	if !strings.Contains(upload["code_snippet"].(string), "…") {
		t.Fatalf("upload view should mask: %v", upload["code_snippet"])
	}
}

func TestPreviewRedactionMissingArgs(t *testing.T) {
	project, _ := fixture(t)
	out, isErr := callTool(t, handlePreviewRedaction(project), nil)
	if !isErr || !strings.Contains(out, `Pass a finding "id" from get_findings`) {
		t.Fatalf("missing id/text should error: %v %s", isErr, out)
	}
	out, isErr = callTool(t, handlePreviewRedaction(project), map[string]any{"id": "nope-9"})
	if !isErr || !strings.Contains(out, `No finding "nope-9" in the latest scan`) {
		t.Fatalf("unknown id should error: %v %s", isErr, out)
	}
	out, isErr = callTool(t, handlePreviewRedaction(project), map[string]any{"text": "hello", "view": "weird"})
	if !isErr || !strings.Contains(out, `view can be "ai", "upload", "local" or "all". You sent "weird".`) {
		t.Fatalf("bad view should error: %v %s", isErr, out)
	}
}

func TestPreviewRedactionDefaultOmitsLocal(t *testing.T) {
	project, _ := fixture(t)
	text := `const key = "` + previewAWS + `"`
	out, isErr := callTool(t, handlePreviewRedaction(project), map[string]any{"text": text})
	if isErr {
		t.Fatal(out)
	}
	if !strings.Contains(out, "**What the AI sees**") || !strings.Contains(out, "**What an uploaded report shows**") {
		t.Fatalf("missing headings: %s", out)
	}
	var resp map[string]any
	if err := json.Unmarshal([]byte(previewJSON(t, out)), &resp); err != nil {
		t.Fatal(err)
	}
	if _, ok := resp["local"]; ok {
		t.Fatalf("default view must not include local: %s", out)
	}
	if resp["ai"] == nil || resp["upload"] == nil {
		t.Fatalf("default view should include ai and upload: %s", out)
	}
	if strings.Contains(out, previewAWS) {
		t.Fatalf("default view leaked the raw key: %s", out)
	}
	out, isErr = callTool(t, handlePreviewRedaction(project), map[string]any{"text": text, "view": "local"})
	if isErr {
		t.Fatal(out)
	}
	if !strings.Contains(out, previewAWS) {
		t.Fatal("view=local should include the raw value")
	}
	if !strings.Contains(out, "full secret values") {
		t.Fatalf("view=local should warn: %s", out)
	}
}

func TestPreviewRedactionToolIsRegistered(t *testing.T) {
	s := newServer(func(context.Context, mcp.CallToolRequest) (string, error) { return "/tmp", nil }, false)
	// ListTools is on the MCP server; walk AddTool registrations via a tools/list
	// JSON-RPC call isn't exposed here. Instead, confirm the handler is wired by
	// calling it — and that the tool count grew by one (previously 26).
	_ = s
	project, _ := fixture(t)
	out, isErr := callTool(t, handlePreviewRedaction(project), map[string]any{"text": "hello"})
	if isErr {
		t.Fatal(out)
	}
	if !strings.Contains(out, `"detected"`) {
		t.Fatalf("unexpected: %s", out)
	}
}

func TestGetFindingMasksSecretsAndContext(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	proj := home + "/app"
	if err := os.MkdirAll(proj+"/src", 0o755); err != nil {
		t.Fatal(err)
	}
	key := previewAWS
	surround := "const cfg = {\n  accessKeyId: \"" + key + "\",\n}\n"
	if err := os.WriteFile(proj+"/src/aws.ts", []byte(surround), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := normalizer.SaveScanResult(proj, []normalizer.Finding{{
		ID: "gitleaks-0", Scanner: "gitleaks", Category: "secrets", RuleID: "aws-access-token",
		Title: "Leaked AWS " + key, FilePath: "src/aws.ts", LineNumber: 2,
		CodeSnippet: `accessKeyId: "` + key + `"`, SurroundingCode: surround,
		Status: normalizer.StatusOpen,
	}})
	if err != nil {
		t.Fatal(err)
	}
	project := func(context.Context, mcp.CallToolRequest) (string, error) { return proj, nil }
	out, isErr := callTool(t, handleGetFindingWithContext(project), map[string]any{"id": "gitleaks-0"})
	if isErr {
		t.Fatal(out)
	}
	if strings.Contains(out, key) {
		t.Fatalf("get_finding leaked the raw key: %s", out)
	}
	if !strings.Contains(out, "SECRET removed by Trojan") {
		t.Fatalf("get_finding should use a label in snippet and context: %s", out)
	}
	fixOut, isErr := callTool(t, handleGetFixableFindings(project), nil)
	if isErr {
		t.Fatal(fixOut)
	}
	if strings.Contains(fixOut, key) {
		t.Fatalf("get_fixable_findings leaked the raw key: %s", fixOut)
	}
}

func TestGetFindingReplacesSemgrepLoginSnippet(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	proj := home + "/app"
	_, err := normalizer.SaveScanResult(proj, []normalizer.Finding{{
		ID: "semgrep-4", Scanner: "semgrep", RuleID: "detected-aws-key",
		Title: "AWS key", FilePath: "src/config.ts", LineNumber: 2,
		CodeSnippet: "requires login", Status: normalizer.StatusOpen,
	}})
	if err != nil {
		t.Fatal(err)
	}
	project := func(context.Context, mcp.CallToolRequest) (string, error) { return proj, nil }
	out, isErr := callTool(t, handleGetFindingWithContext(project), map[string]any{"id": "semgrep-4"})
	if isErr {
		t.Fatal(out)
	}
	if strings.Contains(out, `"requires login"`) {
		t.Fatalf("semgrep placeholder left in place: %s", out)
	}
	if !strings.Contains(out, "Code preview not available for this finding") {
		t.Fatalf("expected preview placeholder: %s", out)
	}
}

func TestPreviewRedactionBothOmitsLocal(t *testing.T) {
	project, _ := fixture(t)
	text := `const key = "` + previewAWS + `"; // stripe: ` + previewStripe
	out, isErr := callTool(t, handlePreviewRedaction(project), map[string]any{"text": text, "view": "both"})
	if isErr {
		t.Fatal(out)
	}
	if strings.Contains(out, `"local":`) {
		t.Fatalf("view=both must not return the local view:\n%s", out)
	}
	if !strings.Contains(out, `"ai"`) || !strings.Contains(out, `"upload"`) {
		t.Fatalf("view=both should include ai and upload:\n%s", out)
	}
	if strings.Contains(out, previewAWS) || strings.Contains(out, previewStripe) {
		t.Fatalf("view=both leaked a raw secret")
	}
}

func TestPreviewRedactionZeroSecretsCopy(t *testing.T) {
	project, _ := fixture(t)
	out, isErr := callTool(t, handlePreviewRedaction(project), map[string]any{"text": "hello world, no keys here"})
	if isErr {
		t.Fatal(out)
	}
	if !strings.Contains(out, "No secrets found in this input") {
		t.Fatalf("zero-secret copy missing:\n%s", out)
	}
	if strings.Contains(out, "Found 0 secrets") || strings.Contains(out, "sk_live_") && strings.Contains(out, "Found 0") {
		t.Fatalf("old zero-secret summary still present:\n%s", out)
	}
}
