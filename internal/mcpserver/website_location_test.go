package mcpserver

import (
	"encoding/json"
	"testing"

	"github.com/dev-zeph/trojan/internal/normalizer"
)

// (e) get_website_findings returns each finding's source file and line (and a
// ready "location"), keeps FilePath as the URL for older clients, and keeps
// each finding's own verdict text.
func TestGetWebsiteFindings_ReturnsFileAndLine(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	normalizer.SaveWebsiteTest("http://127.0.0.1:3000", []normalizer.Finding{ //nolint:errcheck
		{
			ID: "agentic-1", Scanner: "agentic-dast", Category: "dast", Title: "SQL injection in admin customer search",
			FilePath: "http://127.0.0.1:3000/api/admin/customers?q=", URL: "http://127.0.0.1:3000/api/admin/customers?q=",
			SourceFile: "app/api/admin/customers/route.ts", SourceLine: 12,
			Verdict: "confirmed", VerdictReason: "q is concatenated into the LIKE query",
		},
		{
			ID: "agentic-2", Scanner: "agentic-dast", Category: "dast", Title: "Health endpoint leaks env",
			FilePath: "http://127.0.0.1:3000/api/health?verbose=1", // saved before url existed
			Verdict: "confirmed", VerdictReason: "response body contains process.env",
		},
	})

	text, isErr := callTool(t, handleGetWebsiteFindings, map[string]any{"url": "http://127.0.0.1:3000"})
	if isErr {
		t.Fatal(text)
	}
	var got struct {
		Findings []struct {
			ID            string
			FilePath      string
			LineNumber    int
			VerdictReason string
			URL           string `json:"url"`
			SourceFile    string `json:"source_file"`
			SourceLine    int    `json:"source_line"`
			Location      string `json:"location"`
		}
	}
	if err := json.Unmarshal([]byte(text), &got); err != nil {
		t.Fatalf("%v: %s", err, text)
	}
	if len(got.Findings) != 2 {
		t.Fatalf("findings = %s", text)
	}
	a, b := got.Findings[0], got.Findings[1]
	if a.ID != "agentic-1" {
		a, b = b, a
	}
	if a.SourceFile != "app/api/admin/customers/route.ts" || a.SourceLine != 12 || a.Location != "app/api/admin/customers/route.ts:12" {
		t.Errorf("source location missing: %+v", a)
	}
	if a.FilePath != a.URL || a.URL == "" {
		t.Errorf("URL fields: %+v", a)
	}
	if b.URL != "http://127.0.0.1:3000/api/health?verbose=1" || b.SourceFile != "" || b.Location != "" {
		t.Errorf("legacy finding: %+v", b)
	}
	if a.VerdictReason == b.VerdictReason {
		t.Error("findings share verdict text")
	}
}
