package normalizer

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// CodePreviewOrPlaceholder replaces Semgrep's "requires login" snippet, which
// inside Trojan reads as if Trojan itself needs a sign-in, with a clear note.
func CodePreviewOrPlaceholder(snippet, file string, line int) string {
	if strings.EqualFold(strings.TrimSpace(snippet), "requires login") {
		if file == "" {
			return "Code preview not available for this finding."
		}
		if line > 0 {
			return fmt.Sprintf("Code preview not available for this finding. See %s line %d.", file, line)
		}
		return fmt.Sprintf("Code preview not available for this finding. See %s.", file)
	}
	return snippet
}

// RelToProject returns stored as a project-relative slash path when the file
// can be found under root. It accepts paths that were recorded relative to a
// parent working directory (for example fixture/app/src/a.ts when root is
// fixture/app). URLs and empty paths are returned unchanged.
func RelToProject(root, stored string) string {
	if stored == "" || strings.Contains(stored, "://") {
		return stored
	}
	if abs, ok := ResolveAgainstRoot(root, stored); ok {
		if rel, err := filepath.Rel(absRoot(root), abs); err == nil && !strings.HasPrefix(rel, "..") {
			return filepath.ToSlash(rel)
		}
		return filepath.ToSlash(abs)
	}
	return filepath.ToSlash(filepath.Clean(stored))
}

// ResolveAgainstRoot returns the absolute path of a finding file resolved
// against the scan root (not the process working directory). ok is false when
// no existing file can be found.
func ResolveAgainstRoot(root, stored string) (string, bool) {
	if stored == "" || strings.Contains(stored, "://") {
		return "", false
	}
	rootAbs := absRoot(root)
	var candidates []string
	if filepath.IsAbs(stored) {
		candidates = append(candidates, stored)
	} else {
		candidates = append(candidates, filepath.Join(rootAbs, stored))
		if abs, err := filepath.Abs(stored); err == nil {
			candidates = append(candidates, abs)
		}
		parts := splitPath(stored)
		for i := 1; i < len(parts); i++ {
			candidates = append(candidates, filepath.Join(append([]string{rootAbs}, parts[i:]...)...))
		}
	}
	for _, c := range candidates {
		if st, err := os.Stat(c); err == nil && !st.IsDir() {
			if rel, err := filepath.Rel(rootAbs, c); err == nil && !strings.HasPrefix(rel, "..") {
				return c, true
			}
			// Absolute stored path inside root already handled; allow exact abs hits.
			if filepath.IsAbs(stored) {
				return c, true
			}
		}
	}
	return filepath.Join(rootAbs, stored), false
}

func absRoot(root string) string {
	if abs, err := filepath.Abs(root); err == nil {
		return abs
	}
	return root
}

func splitPath(p string) []string {
	p = filepath.ToSlash(filepath.Clean(p))
	p = strings.TrimPrefix(p, "/")
	if p == "" || p == "." {
		return nil
	}
	return strings.Split(p, "/")
}
