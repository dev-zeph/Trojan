package mcpserver

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// ── Connecting AI tools to the local server ──────────────────────────────────
//
// ConnectLocal writes the local server's URL and token into each tool's own
// MCP config, in the file that tool actually reads:
//   - Claude Code: user scope in ~/.claude.json (via `claude mcp add-json` when
//     the CLI is available). ~/.claude/settings.json is NOT read for MCP
//     servers; the old installer wrote there, so that entry is removed.
//   - Cursor:      ~/.cursor/mcp.json
//   - Codex:       ~/.codex/config.toml
// LocalStatus reports what is set up, plus when each tool last used Trojan.

// Tools lists the AI tools the desktop app can connect, by key.
var Tools = []string{"claude_code", "cursor", "codex_cli"}

// ToolStatus is what the desktop app shows for one AI tool.
type ToolStatus struct {
	Installed  bool       `json:"installed"`
	Configured bool       `json:"configured"`
	LastUsed   *time.Time `json:"lastUsed,omitempty"`
	Project    string     `json:"project,omitempty"`
}

// ConnectLocal sets up one AI tool (a key from Tools) to use the local server.
func ConnectLocal(tool string) error {
	token, err := LocalToken()
	if err != nil {
		return err
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	switch tool {
	case "claude_code":
		return connectClaude(home, token)
	case "cursor":
		return setJSONServer(filepath.Join(home, ".cursor", "mcp.json"), map[string]any{
			"url":     LocalURL,
			"headers": map[string]any{"Authorization": "Bearer " + token},
		})
	case "codex_cli":
		return connectCodex(filepath.Join(home, ".codex", "config.toml"), token)
	}
	return fmt.Errorf("unknown tool %q", tool)
}

// LocalStatus reports every tool in Tools.
func LocalStatus() map[string]ToolStatus {
	home, _ := os.UserHomeDir()
	token, _ := LocalToken()
	activity := LoadActivity()
	out := map[string]ToolStatus{}
	for _, t := range Tools {
		st := ToolStatus{}
		switch t {
		case "claude_code":
			st.Installed = dirExists(filepath.Join(home, ".claude")) || onPath("claude")
			st.Configured = jsonServerMatches(filepath.Join(home, ".claude.json"), token)
		case "cursor":
			st.Installed = dirExists(filepath.Join(home, ".cursor"))
			st.Configured = jsonServerMatches(filepath.Join(home, ".cursor", "mcp.json"), token)
		case "codex_cli":
			st.Installed = dirExists(filepath.Join(home, ".codex")) || onPath("codex")
			st.Configured = codexMatches(filepath.Join(home, ".codex", "config.toml"), token)
		}
		if a, ok := activity[t]; ok {
			seen := a.LastSeen
			st.LastUsed, st.Project = &seen, a.Project
		}
		out[t] = st
	}
	return out
}

// ── Claude Code ──────────────────────────────────────────────────────────────

func connectClaude(home, token string) error {
	entry := map[string]any{
		"type":    "http",
		"url":     LocalURL,
		"headers": map[string]any{"Authorization": "Bearer " + token},
	}
	removeLegacyClaudeEntry(filepath.Join(home, ".claude", "settings.json"))

	// Prefer Claude Code's own CLI: it owns ~/.claude.json and knows its format.
	if bin, err := exec.LookPath("claude"); err == nil {
		exec.Command(bin, "mcp", "remove", "trojan", "--scope", "user").Run() //nolint:errcheck // absent is fine
		data, _ := json.Marshal(entry)
		if out, err := exec.Command(bin, "mcp", "add-json", "--scope", "user", "trojan", string(data)).CombinedOutput(); err == nil {
			return nil
		} else {
			fmt.Fprintf(os.Stderr, "claude mcp add-json failed, writing ~/.claude.json directly: %s\n", strings.TrimSpace(string(out)))
		}
	}
	return setJSONServer(filepath.Join(home, ".claude.json"), entry)
}

// removeLegacyClaudeEntry deletes the stdio entry the old installer put in
// ~/.claude/settings.json (Claude Code never loaded it from there).
func removeLegacyClaudeEntry(path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	cfg := map[string]any{}
	if decodeExact(data, &cfg) != nil {
		return
	}
	servers, _ := cfg["mcpServers"].(map[string]any)
	entry, _ := servers["trojan"].(map[string]any)
	if entry == nil || entry["command"] != "trojan" {
		return
	}
	delete(servers, "trojan")
	if len(servers) == 0 {
		delete(cfg, "mcpServers")
	}
	if out, err := json.MarshalIndent(cfg, "", "  "); err == nil {
		writeFileKeepMode(path, append(out, '\n'))
	}
}

// ── JSON configs (Cursor, ~/.claude.json fallback) ───────────────────────────

// setJSONServer sets mcpServers.trojan in a JSON config, replacing any earlier
// Trojan entry and keeping everything else. It refuses to touch a file it
// can't parse rather than overwrite the user's other settings.
func setJSONServer(path string, entry map[string]any) error {
	cfg := map[string]any{}
	if data, err := os.ReadFile(path); err == nil && len(strings.TrimSpace(string(data))) > 0 {
		if err := decodeExact(data, &cfg); err != nil {
			return fmt.Errorf("%s isn't valid JSON, so it was left alone: %w", path, err)
		}
	}
	servers, _ := cfg["mcpServers"].(map[string]any)
	if servers == nil {
		servers = map[string]any{}
	}
	servers["trojan"] = entry
	cfg["mcpServers"] = servers

	out, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	return writeFileKeepMode(path, append(out, '\n'))
}

func jsonServerMatches(path, token string) bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	var cfg struct {
		MCPServers map[string]struct {
			URL     string            `json:"url"`
			Headers map[string]string `json:"headers"`
		} `json:"mcpServers"`
	}
	if json.Unmarshal(data, &cfg) != nil {
		return false
	}
	e, ok := cfg.MCPServers["trojan"]
	return ok && e.URL == LocalURL && e.Headers["Authorization"] == "Bearer "+token
}

// ── Codex (TOML) ─────────────────────────────────────────────────────────────

func codexSection(token string) string {
	return fmt.Sprintf("[mcp_servers.trojan]\nurl = %q\nhttp_headers = { \"Authorization\" = %q }\n", LocalURL, "Bearer "+token)
}

func connectCodex(path, token string) error {
	existing := ""
	if data, err := os.ReadFile(path); err == nil {
		existing = string(data)
	}
	rest := strings.TrimRight(removeTOMLTable(existing, "mcp_servers.trojan"), "\n")
	if rest != "" {
		rest += "\n\n"
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	return writeFileKeepMode(path, []byte(rest+codexSection(token)))
}

func codexMatches(path, token string) bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	return strings.Contains(string(data), codexSection(token))
}

// removeTOMLTable drops a [table] and its [table.sub] tables, up to the next
// unrelated table header. Line-based: enough for the tables Trojan writes.
func removeTOMLTable(content, table string) string {
	var out []string
	skipping := false
	for _, line := range strings.Split(content, "\n") {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "[") {
			name := strings.Trim(t, "[] ")
			skipping = name == table || strings.HasPrefix(name, table+".")
		}
		if !skipping {
			out = append(out, line)
		}
	}
	return strings.Join(out, "\n")
}

// ── helpers ──────────────────────────────────────────────────────────────────

// decodeExact decodes JSON keeping numbers as written, so rewriting a config
// (e.g. ~/.claude.json, which stores large IDs and timestamps) can't round them.
func decodeExact(data []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	return dec.Decode(v)
}

func onPath(bin string) bool {
	_, err := exec.LookPath(bin)
	return err == nil
}

// writeFileKeepMode writes via a temp file + rename so a crash can't leave a
// half-written config, keeping the original file's permissions.
func writeFileKeepMode(path string, data []byte) error {
	mode := os.FileMode(0644)
	if info, err := os.Stat(path); err == nil {
		mode = info.Mode().Perm()
	}
	tmp := path + ".trojan-tmp"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
