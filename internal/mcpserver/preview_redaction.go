package mcpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"

	"github.com/dev-zeph/trojan/internal/normalizer"
	"github.com/dev-zeph/trojan/internal/redact"
)

// previewSecret is one detected secret in a preview_redaction reply.
type previewSecret struct {
	Type    string   `json:"type"`
	Length  int      `json:"length"`
	Prefix  string   `json:"prefix,omitempty"`
	Looks   string   `json:"looks"`
	Entropy float64  `json:"entropy"`
	Checks  []string `json:"checks,omitempty"`
	File    string   `json:"file,omitempty"`
	Line    int      `json:"line,omitempty"`
}

// handlePreviewRedaction powers the preview_redaction MCP tool. The default
// reply is the AI view and the upload view only: the local unmasked view is
// returned only when the caller opts in with view="local" or view="all", and
// then with a warning that the reply goes to the assistant.
func handlePreviewRedaction(project projectFunc) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		view := strings.ToLower(strings.TrimSpace(req.GetString("view", "")))
		if view == "both" {
			// Historical alias for the default (ai + upload). Never treat it
			// as "all", which would send full local values.
			view = ""
		}
		switch view {
		case "", "ai", "upload", "local", "all":
		default:
			return mcp.NewToolResultError(fmt.Sprintf(`view can be "ai", "upload", "local" or "all". You sent %q.`, view)), nil
		}
		// view=local is additive: it also includes the AI and upload views.
		showAI := view == "" || view == "ai" || view == "local" || view == "all"
		showUpload := view == "" || view == "upload" || view == "local" || view == "all"
		showLocal := view == "local" || view == "all"

		text := req.GetString("text", "")
		id := req.GetString("id", "")

		switch {
		case text != "":
			fd := &redact.Finder{}
			detected := classifyPreview("", 0, text)
			resp := map[string]any{
				"input":    "text",
				"detected": detected,
			}
			if showLocal {
				resp["local"] = text
			}
			if showAI {
				resp["ai"] = fd.Redact(text)
			}
			if showUpload {
				resp["upload"] = fd.Mask(text)
			}
			return previewResult(detected, resp, showLocal)

		case id != "":
			projectPath, err := project(ctx, req)
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			scan, err := loadLatestScan(projectPath)
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			var found *normalizer.Finding
			for i := range scan.Findings {
				if scan.Findings[i].ID == id {
					found = &scan.Findings[i]
					break
				}
			}
			if found == nil {
				return mcp.NewToolResultError(fmt.Sprintf("No finding %q in the latest scan. Run get_findings to see current ids. Ids can change after a new scan.", id)), nil
			}
			blob := found.CodeSnippet + "\n" + found.SurroundingCode + "\n" + found.RawMessage
			detected := classifyPreview(found.FilePath, found.LineNumber, blob)
			resp := map[string]any{
				"input":    "finding",
				"id":       id,
				"detected": detected,
			}
			if showLocal {
				resp["local"] = compactFinding(*found)
			}
			if showAI {
				resp["ai"] = compactFinding(redact.ForAI(*found))
			}
			if showUpload {
				resp["upload"] = compactFinding(redact.ForUpload(*found))
			}
			return previewResult(detected, resp, showLocal)

		default:
			return mcp.NewToolResultError(`Pass a finding "id" from get_findings, or some "text" to test, like STRIPE_SECRET_KEY=` + "sk_" + "live_" + "abc123."), nil
		}
	}
}

func classifyPreview(path string, line int, s string) []previewSecret {
	out := []previewSecret{}
	for _, sec := range redact.Find(s) {
		a := redact.Classify(sec.Value, sec.Type, path)
		out = append(out, previewSecret{
			Type:    sec.Type,
			Length:  len(sec.Value),
			Prefix:  redact.SafePrefixFor(sec),
			Looks:   redact.Looks(a.Class),
			Entropy: round2(redact.Entropy(sec.Value)),
			Checks:  a.Checks,
			File:    path,
			Line:    line,
		})
	}
	return out
}

func previewResult(detected []previewSecret, resp map[string]any, includeLocal bool) (*mcp.CallToolResult, error) {
	data, err := json.MarshalIndent(resp, "", "  ")
	if err != nil {
		return mcp.NewToolResultError("failed to serialize result"), nil
	}
	var b strings.Builder
	b.WriteString(previewSummary(detected, resp["input"]))
	if includeLocal {
		b.WriteString("\nWarning: the local view includes the full secret values and will go to your AI assistant.\n")
	}
	b.WriteByte('\n')
	b.Write(data)
	return mcp.NewToolResultText(b.String()), nil
}

func previewSummary(detected []previewSecret, input any) string {
	kind, _ := input.(string)
	if len(detected) == 0 {
		if kind == "finding" {
			return "**No code preview for this finding.** Semgrep doesn't share the matching line. When Trojan sends this finding to its AI, the code around it goes through the same secret swap.\n"
		}
		return "**No secrets found in this input.** Nothing here needed swapping. If you expected a secret, it may be in a format Trojan doesn't detect yet.\n"
	}
	var b strings.Builder
	b.WriteString("**What Trojan does with secrets in this code**\n")
	if len(detected) == 1 {
		b.WriteString("Found 1 secret. Trojan swaps each one for a label before its AI models see the code. Anything not listed here was not detected and is not swapped.\n")
	} else {
		fmt.Fprintf(&b, "Found %d secrets. Trojan swaps each one for a label before its AI models see the code. Anything not listed here was not detected and is not swapped.\n", len(detected))
	}
	b.WriteString("\n**What the AI sees**\n")
	b.WriteString("A label for each secret, like `<SECRET removed by Trojan: type=stripe_secret_key, len=32, prefix=sk_live_, looks=real>`. It says what kind of key it is and how long it is. It does not include the key.\n")
	b.WriteString("\n**What an uploaded report shows**\n")
	b.WriteString("The start and last 4 characters, like `sk_live_…1vW4`, so you can tell which key it is. Short or generic secrets show only their length.\n")
	b.WriteString("\n**What stays on your computer**\n")
	b.WriteString("The full values stay in your files and in Trojan's local scan results. Ask for view=\"local\" to see them here.\n")
	b.WriteString("\n**Secrets found**\n")
	for _, s := range detected {
		fmt.Fprintf(&b, "- %s", friendlySecretType(s.Type, s.Prefix))
		fmt.Fprintf(&b, ", %d characters", s.Length)
		if s.File != "" {
			fmt.Fprintf(&b, ", in %s", s.File)
			if s.Line > 0 {
				fmt.Fprintf(&b, " line %d", s.Line)
			}
		}
		b.WriteString(". ")
		b.WriteString(looksSentence(s.Looks, s.Type, s.Checks))
		b.WriteByte('\n')
	}
	return b.String()
}

func looksSentence(looks, typ string, checks []string) string {
	if looks == "placeholder" {
		if why := checksPhrase(typ, checks); why != "" {
			return "Looks like a placeholder: " + why + "."
		}
		return "Looks like a placeholder."
	}
	return "Looks real."
}

func checksPhrase(typ string, checks []string) string {
	var parts []string
	for _, c := range checks {
		switch c {
		case "checksum_invalid":
			parts = append(parts, "it fails "+providerPossessive(typ)+" format check")
		case "test_path":
			parts = append(parts, "it is in an example or test file")
		case "placeholder_pattern":
			parts = append(parts, "it looks like sample text")
		case "low_entropy":
			parts = append(parts, "it is too simple to be a real key")
		case "provider_docs_example":
			parts = append(parts, "it matches the provider's documentation example")
		}
	}
	return strings.Join(parts, "; ")
}

func friendlySecretType(typ, prefix string) string {
	switch typ {
	case "stripe_secret_key":
		if strings.Contains(prefix, "live") {
			return "Stripe secret key (live)"
		}
		if strings.Contains(prefix, "test") {
			return "Stripe secret key (test)"
		}
		return "Stripe secret key"
	case "stripe_restricted_key":
		return "Stripe restricted key"
	case "stripe_webhook_secret":
		return "Stripe webhook secret"
	case "github_token", "github_fine_grained_pat":
		return "GitHub token"
	case "aws_access_key":
		return "AWS access key"
	case "aws_secret_key":
		return "AWS secret key"
	case "openai_api_key":
		return "OpenAI API key"
	case "anthropic_api_key":
		return "Anthropic API key"
	case "google_api_key":
		return "Google API key"
	case "slack_token", "slack_webhook":
		return "Slack token"
	case "npm_token":
		return "npm token"
	case "sendgrid_api_key":
		return "SendGrid API key"
	case "twilio_api_key":
		return "Twilio API key"
	case "private_key":
		return "Private key"
	case "jwt":
		return "JWT"
	case "url_password", "password":
		return "Password"
	case "url_query":
		return "URL parameter"
	case "url_path":
		return "URL path"
	case "http_header", "authorization_header":
		return "HTTP header"
	case "cookie_header", "session_cookie":
		return "Cookie value"
	case "generic_secret":
		return "Secret"
	default:
		return strings.ReplaceAll(typ, "_", " ")
	}
}

// compactFinding is the subset of a finding whose fields can carry a secret,
// shown so the three views can be compared field by field.
func providerPossessive(typ string) string {
	switch typ {
	case "github_token", "github_fine_grained_pat":
		return "GitHub's"
	case "npm_token":
		return "npm's"
	case "aws_access_key", "aws_secret_key":
		return "AWS's"
	case "stripe_secret_key", "stripe_restricted_key", "stripe_webhook_secret":
		return "Stripe's"
	default:
		return "the provider's"
	}
}

func compactFinding(f normalizer.Finding) map[string]any {
	return map[string]any{
		"title":            f.Title,
		"location":         f.FilePath,
		"rule":             f.RuleID,
		"code_snippet":     f.CodeSnippet,
		"surrounding_code": f.SurroundingCode,
		"raw_message":      f.RawMessage,
	}
}

func round2(f float64) float64 {
	return float64(int(f*100+0.5)) / 100
}
