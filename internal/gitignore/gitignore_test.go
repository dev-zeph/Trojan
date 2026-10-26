package gitignore

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEnsureTrojanIgnored(t *testing.T) {
	repo := t.TempDir()
	os.Mkdir(filepath.Join(repo, ".git"), 0755)                                   //nolint:errcheck
	os.WriteFile(filepath.Join(repo, ".gitignore"), []byte("node_modules"), 0644) // no trailing newline

	EnsureTrojanIgnored(repo)
	EnsureTrojanIgnored(repo) // idempotent

	data, _ := os.ReadFile(filepath.Join(repo, ".gitignore"))
	got := string(data)
	if !strings.HasPrefix(got, "node_modules\n") || strings.Count(got, ".trojan/*") != 1 || !strings.Contains(got, "!.trojan/context.yaml") {
		t.Errorf(".gitignore =\n%s", got)
	}
}

func TestSubfolderProjectAndExistingRule(t *testing.T) {
	repo := t.TempDir()
	os.Mkdir(filepath.Join(repo, ".git"), 0755)                                  //nolint:errcheck
	os.WriteFile(filepath.Join(repo, ".gitignore"), []byte("/.trojan/\n"), 0644) //nolint:errcheck
	sub := filepath.Join(repo, "frontend")
	os.Mkdir(sub, 0755) //nolint:errcheck

	EnsureTrojanIgnored(sub)
	if _, err := os.Stat(filepath.Join(sub, ".gitignore")); err == nil {
		t.Error("wrote a .gitignore although the repo already ignores .trojan")
	}
}

func TestNotARepo(t *testing.T) {
	dir := t.TempDir()
	EnsureTrojanIgnored(dir)
	if _, err := os.Stat(filepath.Join(dir, ".gitignore")); err == nil {
		t.Error("created .gitignore outside a git repo")
	}
}
