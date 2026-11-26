package scanners

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestSkippedLocalEnvFilesOutsideGit(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("X=1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".env.example"), []byte("X=\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	got := SkippedLocalEnvFiles(dir)
	if len(got) != 1 || got[0] != ".env" {
		t.Fatalf("outside git: skipped=%v, want [.env]", got)
	}
	if !ProjectSkippedLocalEnv(dir) {
		t.Fatal("expected ProjectSkippedLocalEnv")
	}
}

func TestSkippedLocalEnvFilesGitignored(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	dir := t.TempDir()
	run := func(args ...string) {
		t.Helper()
		cmd := exec.Command(args[0], args[1:]...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("%v: %s", args, out)
		}
	}
	run("git", "init")
	if err := os.WriteFile(filepath.Join(dir, ".gitignore"), []byte(".env\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("X=1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".env.example"), []byte("X=\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	got := SkippedLocalEnvFiles(dir)
	if len(got) != 1 || got[0] != ".env" {
		t.Fatalf("gitignored: skipped=%v, want [.env]", got)
	}
}

func TestSkippedLocalEnvFilesTrackedEnv(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	dir := t.TempDir()
	run := func(args ...string) {
		t.Helper()
		cmd := exec.Command(args[0], args[1:]...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("%v: %s", args, out)
		}
	}
	run("git", "init")
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("X=1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	run("git", "add", "-f", ".env")
	if skipped := SkippedLocalEnvFiles(dir); len(skipped) != 0 {
		t.Fatalf("tracked .env should not be skipped, got %v", skipped)
	}
}
