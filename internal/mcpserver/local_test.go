package mcpserver

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGuard(t *testing.T) {
	ok := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	h := guard(func() string { return "secret" }, ok)

	cases := []struct {
		host, auth string
		want       int
	}{
		{"127.0.0.1:7880", "Bearer secret", http.StatusOK},
		{"localhost:7880", "Bearer secret", http.StatusOK},
		{"127.0.0.1:7880", "Bearer wrong", http.StatusUnauthorized},
		{"127.0.0.1:7880", "", http.StatusUnauthorized},
		{"evil.example:7880", "Bearer secret", http.StatusForbidden}, // DNS rebinding
	}
	for _, c := range cases {
		req := httptest.NewRequest("POST", "/mcp", nil)
		req.Host = c.host
		if c.auth != "" {
			req.Header.Set("Authorization", c.auth)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != c.want {
			t.Errorf("host=%s auth=%q: got %d, want %d", c.host, c.auth, rec.Code, c.want)
		}
	}
}

func TestFindScannedProject(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, ".trojan", "scans"), 0755); err != nil {
		t.Fatal(err)
	}
	sub := filepath.Join(root, "src", "api")
	os.MkdirAll(sub, 0755) //nolint:errcheck

	if got, ok := findScannedProject(sub); !ok || got != root {
		t.Errorf("from subfolder: got %q, %v; want %q", got, ok, root)
	}
	if _, ok := findScannedProject(t.TempDir()); ok {
		t.Error("found a project in an unscanned folder")
	}
}

func TestToolKey(t *testing.T) {
	for in, want := range map[string]string{"claude-code": "claude_code", "Cursor": "cursor", "codex-mcp-client": "codex_cli", "": ""} {
		if got := ToolKey(in); got != want {
			t.Errorf("ToolKey(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestRemoveTOMLTable(t *testing.T) {
	in := `model = "o3"

[mcp_servers.other]
command = "x"

[mcp_servers.trojan]
command = "trojan"
args = ["mcp"]

[mcp_servers.trojan.env]
A = "1"

[profiles.fast]
model = "mini"
`
	out := removeTOMLTable(in, "mcp_servers.trojan")
	if strings.Contains(out, "trojan") {
		t.Errorf("trojan tables not removed:\n%s", out)
	}
	for _, keep := range []string{`model = "o3"`, "[mcp_servers.other]", "[profiles.fast]", `model = "mini"`} {
		if !strings.Contains(out, keep) {
			t.Errorf("lost %q:\n%s", keep, out)
		}
	}
}

func TestConnectAndStatus(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("PATH", "") // no claude/codex CLIs: exercise the direct-write paths
	for _, d := range []string{".claude", ".cursor", ".codex"} {
		os.MkdirAll(filepath.Join(home, d), 0755) //nolint:errcheck
	}
	// Existing user settings that must survive, plus the old broken entry.
	os.WriteFile(filepath.Join(home, ".claude", "settings.json"), //nolint:errcheck
		[]byte(`{"theme":"dark","mcpServers":{"trojan":{"command":"trojan","args":["mcp"]}}}`), 0644)
	os.WriteFile(filepath.Join(home, ".claude.json"), //nolint:errcheck
		[]byte(`{"userID":"x","firstStartTime":1761460000123456789,"mcpServers":{"other":{"type":"http","url":"https://x"}}}`), 0644)
	os.WriteFile(filepath.Join(home, ".codex", "config.toml"), //nolint:errcheck
		[]byte("model = \"o3\"\n\n[mcp_servers.trojan]\ncommand = \"trojan\"\nargs = [\"mcp\"]\n"), 0644)

	if st := LocalStatus(); st["cursor"].Configured || !st["cursor"].Installed {
		t.Fatalf("before connect: %+v", st["cursor"])
	}
	for _, tool := range Tools {
		if err := ConnectLocal(tool); err != nil {
			t.Fatalf("ConnectLocal(%s): %v", tool, err)
		}
	}
	for tool, st := range LocalStatus() {
		if !st.Configured {
			t.Errorf("%s not configured after connect", tool)
		}
	}

	claudeJSON, _ := os.ReadFile(filepath.Join(home, ".claude.json"))
	for _, keep := range []string{`"userID": "x"`, `1761460000123456789`, `"other"`, LocalURL} {
		if !strings.Contains(string(claudeJSON), keep) {
			t.Errorf(".claude.json missing %s:\n%s", keep, claudeJSON)
		}
	}
	settings, _ := os.ReadFile(filepath.Join(home, ".claude", "settings.json"))
	if strings.Contains(string(settings), "trojan") || !strings.Contains(string(settings), "dark") {
		t.Errorf("legacy entry not cleaned up correctly:\n%s", settings)
	}
	codex, _ := os.ReadFile(filepath.Join(home, ".codex", "config.toml"))
	if strings.Count(string(codex), "[mcp_servers.trojan]") != 1 || strings.Contains(string(codex), `command = "trojan"`) || !strings.Contains(string(codex), `model = "o3"`) {
		t.Errorf("codex config wrong:\n%s", codex)
	}

	// Connecting twice must not duplicate anything.
	if err := ConnectLocal("codex_cli"); err != nil {
		t.Fatal(err)
	}
	codex, _ = os.ReadFile(filepath.Join(home, ".codex", "config.toml"))
	if strings.Count(string(codex), "[mcp_servers.trojan]") != 1 {
		t.Errorf("duplicate section after reconnect:\n%s", codex)
	}
}

func TestSetJSONServerRefusesBrokenFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mcp.json")
	os.WriteFile(path, []byte("{not json"), 0644) //nolint:errcheck
	if err := setJSONServer(path, map[string]any{"url": LocalURL}); err == nil {
		t.Error("expected an error for an unparseable file")
	}
	if data, _ := os.ReadFile(path); string(data) != "{not json" {
		t.Error("broken file was overwritten")
	}
}

// Regression: the server and the status check used to race to create the
// token, leaving the server holding one the configs didn't have (401s).
func TestLocalTokenConcurrentCreate(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	const n = 16
	got := make(chan string, n)
	for i := 0; i < n; i++ {
		go func() { tok, _ := LocalToken(); got <- tok }()
	}
	first := <-got
	for i := 1; i < n; i++ {
		if tok := <-got; tok != first || tok == "" {
			t.Fatalf("concurrent callers got different tokens: %q vs %q", first, tok)
		}
	}
}
