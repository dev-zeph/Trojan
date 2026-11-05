package scanners

import (
	"errors"
	"runtime"
	"testing"
)

func TestGitUsable(t *testing.T) {
	origLookup, origDev := gitLookup, devToolsInstalled
	defer func() { gitLookup, devToolsInstalled = origLookup, origDev }()

	gitLookup = func(string) (string, error) { return "", errors.New("not found") }
	if gitUsable() {
		t.Error("no git on PATH should be unusable")
	}
	gitLookup = func(string) (string, error) { return "/opt/homebrew/bin/git", nil }
	if !gitUsable() {
		t.Error("a real git install should be usable")
	}
	if runtime.GOOS == "darwin" {
		gitLookup = func(string) (string, error) { return "/usr/bin/git", nil }
		devToolsInstalled = func() bool { return false }
		if gitUsable() {
			t.Error("Apple's git stub without developer tools must count as unusable (it pops up a dialog)")
		}
		devToolsInstalled = func() bool { return true }
		if !gitUsable() {
			t.Error("/usr/bin/git with developer tools installed is usable")
		}
	}
}
