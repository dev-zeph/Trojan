// Package gitignore keeps Trojan's per-project folder out of git.
package gitignore

import (
	"os"
	"path/filepath"
	"strings"
)

// Block is appended to a project's .gitignore. Scans and reports contain
// findings (code snippets, secrets Trojan found) and must not be committed;
// context.yaml only describes the app, so a team can share it.
const Block = "\n# Trojan: local scan results and reports (context.yaml stays shareable)\n.trojan/*\n!.trojan/context.yaml\n"

// EnsureTrojanIgnored adds Block to <projectDir>/.gitignore when the project
// is inside a git repository and .trojan isn't ignored yet. Best effort: a
// failure never blocks a scan.
func EnsureTrojanIgnored(projectDir string) {
	repoRoot, ok := findRepoRoot(projectDir)
	if !ok {
		return
	}
	for _, f := range []string{filepath.Join(projectDir, ".gitignore"), filepath.Join(repoRoot, ".gitignore")} {
		if mentionsTrojan(f) {
			return
		}
	}
	path := filepath.Join(projectDir, ".gitignore")
	existing, _ := os.ReadFile(path)
	block := Block
	if len(existing) == 0 {
		block = strings.TrimPrefix(block, "\n")
	} else if !strings.HasSuffix(string(existing), "\n") {
		block = "\n" + block
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer f.Close()
	f.WriteString(block) //nolint:errcheck
}

// findRepoRoot walks up from dir to the folder containing .git (a directory,
// or a file for worktrees and submodules).
func findRepoRoot(dir string) (string, bool) {
	dir, err := filepath.Abs(dir)
	if err != nil {
		return "", false
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, ".git")); err == nil {
			return dir, true
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", false
		}
		dir = parent
	}
}

// mentionsTrojan reports whether a .gitignore already has a .trojan rule
// (".trojan", "/.trojan/", ".trojan/*", "**/.trojan" ...).
func mentionsTrojan(path string) bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(data), "\n") {
		l := strings.TrimSpace(line)
		l = strings.TrimPrefix(strings.TrimPrefix(l, "**/"), "/")
		l = strings.TrimSuffix(strings.TrimSuffix(l, "*"), "/")
		if l == ".trojan" {
			return true
		}
	}
	return false
}
