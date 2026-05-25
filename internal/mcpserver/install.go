package mcpserver

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/fatih/color"
)

type editor struct {
	name    string
	detect  string // path that must exist to consider the editor installed
	install func(home string) (skipped bool, err error)
}

// Install auto-configures every detected AI editor to use the Trojan MCP server.
func Install() error {
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("could not find home directory: %w", err)
	}

	editors := []editor{
		{
			name:   "Claude Code",
			detect: filepath.Join(home, ".claude"),
			install: func(home string) (bool, error) {
				return installJSON(filepath.Join(home, ".claude", "settings.json"))
			},
		},
		{
			name:   "Cursor",
			detect: filepath.Join(home, ".cursor"),
			install: func(home string) (bool, error) {
				return installJSON(filepath.Join(home, ".cursor", "mcp.json"))
			},
		},
		{
			name:   "Codex CLI",
			detect: filepath.Join(home, ".codex"),
			install: func(home string) (bool, error) {
				return installTOML(filepath.Join(home, ".codex", "config.toml"))
			},
		},
	}

	found := false
	for _, e := range editors {
		if !dirExists(e.detect) {
			continue
		}
		found = true

		skipped, err := e.install(home)
		if err != nil {
			color.Red("  ✗ %-14s %s\n", e.name, err)
			continue
		}
		if skipped {
			color.Yellow("  ~ %-14s already configured — skipped\n", e.name)
		} else {
			color.Green("  ✓ %-14s configured\n", e.name)
		}
	}

	if !found {
		color.Yellow("No supported editors detected.\n")
		fmt.Println("Supported: Claude Code, Cursor, Codex CLI")
		fmt.Println("\nManual setup — add this to your editor's MCP config:")
		printManual()
		return nil
	}

	fmt.Println()
	fmt.Println("Trojan MCP is ready.")
	fmt.Println("Open your editor, run a scan first if you haven't:")
	fmt.Println()
	fmt.Println("  trojan scan")
	fmt.Println()
	fmt.Println("Try asking your AI agent or copilot: \"show me my Trojan vulnerability findings\"")
	return nil
}

// installJSON merges the trojan MCP entry into a JSON settings file.
// Returns (true, nil) if the entry was already present.
func installJSON(path string) (skipped bool, err error) {
	cfg := map[string]any{}

	if data, err := os.ReadFile(path); err == nil {
		// Ignore parse errors — we'll just overwrite with a valid file
		json.Unmarshal(data, &cfg) //nolint:errcheck
	}

	servers, _ := cfg["mcpServers"].(map[string]any)
	if servers == nil {
		servers = map[string]any{}
	}

	// Already configured — don't overwrite
	if _, exists := servers["trojan"]; exists {
		return true, nil
	}

	servers["trojan"] = map[string]any{
		"command": "trojan",
		"args":    []string{"mcp"},
	}
	cfg["mcpServers"] = servers

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return false, err
	}

	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return false, err
	}
	return false, os.WriteFile(path, data, 0644)
}

// installTOML appends the trojan MCP section to a TOML config file.
// Returns (true, nil) if the section was already present.
func installTOML(path string) (skipped bool, err error) {
	const section = "\n[mcp_servers.trojan]\ncommand = \"trojan\"\nargs = [\"mcp\"]\n"

	existing := ""
	if data, err := os.ReadFile(path); err == nil {
		existing = string(data)
	}

	if strings.Contains(existing, "[mcp_servers.trojan]") {
		return true, nil
	}

	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return false, err
	}

	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return false, err
	}
	defer f.Close()
	_, err = f.WriteString(section)
	return false, err
}

func dirExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

func printManual() {
	fmt.Println()
	fmt.Println("  JSON editors (Claude Code, Cursor):")
	fmt.Println(`  {`)
	fmt.Println(`    "mcpServers": {`)
	fmt.Println(`      "trojan": { "command": "trojan", "args": ["mcp"] }`)
	fmt.Println(`    }`)
	fmt.Println(`  }`)
	fmt.Println()
	fmt.Println("  TOML editors (Codex CLI):")
	fmt.Println(`  [mcp_servers.trojan]`)
	fmt.Println(`  command = "trojan"`)
	fmt.Println(`  args = ["mcp"]`)
}
