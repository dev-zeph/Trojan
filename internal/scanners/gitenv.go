package scanners

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
)

// On a Mac without Apple's developer tools, /usr/bin/git is a stub: running it
// pops up the "install command line developer tools?" dialog and then fails.
// Bearer and Semgrep both call git when a project is a git repository, so
// without help a new user would see that dialog and lose those scanners.
//
// When git isn't really usable, scanners get a stand-in git (first on PATH)
// that just answers "not a git repository". Bearer and Semgrep then scan the
// files directly, and Gitleaks scans files instead of history (--no-git).

var (
	gitOnce   sync.Once
	gitWorks  bool
	gitLookup = exec.LookPath
	// devToolsInstalled reports whether Apple's developer tools are present.
	// xcode-select itself is a real binary and never shows the dialog.
	devToolsInstalled = func() bool {
		return exec.Command("/usr/bin/xcode-select", "-p").Run() == nil
	}
)

// gitUsable reports whether running git will work without side effects.
func gitUsable() bool {
	path, err := gitLookup("git")
	if err != nil {
		return false
	}
	if runtime.GOOS == "darwin" && filepath.Clean(path) == "/usr/bin/git" {
		return devToolsInstalled()
	}
	return true
}

// prepareGit runs once per process before any scanner: if git isn't usable,
// it puts the stand-in git first on PATH for every scanner started after it.
func prepareGit() {
	gitOnce.Do(func() {
		gitWorks = gitUsable()
		if gitWorks {
			return
		}
		dir, err := writeGitShim()
		if err != nil {
			return
		}
		os.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH")) //nolint:errcheck // best effort
	})
}

// writeGitShim writes the stand-in git into ~/.trojan/shims and returns that
// folder.
func writeGitShim() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(home, ".trojan", "shims")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	name, body := "git", "#!/bin/sh\necho 'fatal: not a git repository (or any of the parent directories): .git' >&2\nexit 128\n"
	if runtime.GOOS == "windows" {
		name, body = "git.cmd", "@echo fatal: not a git repository (or any of the parent directories): .git 1>&2\r\n@exit /b 128\r\n"
	}
	path := filepath.Join(dir, name)
	if cur, err := os.ReadFile(path); err != nil || !strings.EqualFold(string(cur), body) {
		if err := os.WriteFile(path, []byte(body), 0o755); err != nil {
			return "", err
		}
	}
	return dir, nil
}

// gitAvailable reports whether scanners can rely on real git (call after
// prepareGit).
func gitAvailable() bool {
	prepareGit()
	return gitWorks
}
