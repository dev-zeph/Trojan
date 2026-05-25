package hook

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	// marker is the magic comment written into the hook file so Trojan can
	// recognise hooks it owns.
	marker = "# trojan"

	// hookScript is the full content of the pre-commit hook that Trojan writes.
	hookScript = `#!/bin/sh
# trojan
# Pre-commit hook installed by Trojan security scanner.
# Run ` + "`trojan hook uninstall`" + ` to remove this hook.

trojan scan --pre-commit
exit $?
`
)

// hookPath returns the absolute path to the pre-commit hook file, starting
// from the given root directory.
func hookPath(root string) string {
	return filepath.Join(root, ".git", "hooks", "pre-commit")
}

// isGitRepo returns true when root contains a .git directory.
func isGitRepo(root string) bool {
	info, err := os.Stat(filepath.Join(root, ".git"))
	return err == nil && info.IsDir()
}

// hasMarker reports whether the file at path contains the Trojan marker line.
func hasMarker(path string) bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	return strings.Contains(string(data), marker)
}

// Install writes the Trojan pre-commit hook into the .git/hooks directory of
// root. It returns an error when:
//   - root is not a git repository
//   - a pre-commit hook already exists and was NOT written by Trojan
//
// When a Trojan-owned hook already exists the function prints a notice and
// returns nil (idempotent).
func Install(root string) error {
	if !isGitRepo(root) {
		return errors.New("not a git repository")
	}

	path := hookPath(root)

	if _, err := os.Stat(path); err == nil {
		// File exists — check ownership.
		if hasMarker(path) {
			fmt.Println("trojan hook: already installed — skipped")
			return nil
		}
		return fmt.Errorf(
			"a pre-commit hook already exists at %s and was not installed by Trojan.\n"+
				"Add `trojan scan --pre-commit` to your existing hook manually, or remove it and re-run `trojan hook install`.",
			path,
		)
	}

	// Ensure the hooks directory exists (it usually does, but just in case).
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("could not create hooks directory: %w", err)
	}

	if err := os.WriteFile(path, []byte(hookScript), 0o755); err != nil {
		return fmt.Errorf("could not write hook: %w", err)
	}

	fmt.Printf("trojan hook: installed pre-commit hook at %s\n", path)
	return nil
}

// Uninstall removes the Trojan-owned pre-commit hook from root. It returns an
// error when:
//   - root is not a git repository
//   - no pre-commit hook exists
//   - the hook exists but was NOT written by Trojan (safety guard)
func Uninstall(root string) error {
	if !isGitRepo(root) {
		return errors.New("not a git repository")
	}

	path := hookPath(root)

	if _, err := os.Stat(path); os.IsNotExist(err) {
		return fmt.Errorf("no pre-commit hook found at %s", path)
	}

	if !hasMarker(path) {
		return fmt.Errorf(
			"the pre-commit hook at %s was not installed by Trojan — refusing to remove it.\n"+
				"Remove it manually if you no longer need it.",
			path,
		)
	}

	if err := os.Remove(path); err != nil {
		return fmt.Errorf("could not remove hook: %w", err)
	}

	fmt.Printf("trojan hook: removed pre-commit hook from %s\n", path)
	return nil
}
