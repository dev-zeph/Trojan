package routes

import (
	"io/fs"
	"path/filepath"
	"strings"

	"github.com/dev-zeph/trojan/internal/normalizer"
)

// walkFiles returns absolute paths of files under root with one of the given
// extensions, skipping non-shipping directories (deps/build/test/generated) and
// dot dirs — the same exclusions the finding path filter uses. Used by the
// call-registered extractors (Express/FastAPI/Gin), which must scan source
// rather than read the route tree off the filesystem.
func walkFiles(root string, exts map[string]bool) []string {
	var out []string
	filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			rel = path
		}
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			if rel == "." {
				return nil
			}
			if normalizer.IsNonShipping(rel) || strings.HasPrefix(d.Name(), ".") {
				return fs.SkipDir
			}
			return nil
		}
		if exts[strings.ToLower(filepath.Ext(path))] && !normalizer.IsNonShipping(rel) {
			out = append(out, path)
		}
		return nil
	})
	return out
}

// joinPath concatenates a route prefix and a local path into a clean canonical
// path, collapsing duplicate slashes and dropping a trailing slash.
func joinPath(prefix, local string) string {
	p := "/" + strings.Trim(prefix, "/") + "/" + strings.Trim(local, "/")
	for strings.Contains(p, "//") {
		p = strings.ReplaceAll(p, "//", "/")
	}
	if len(p) > 1 {
		p = strings.TrimSuffix(p, "/")
	}
	if p == "" {
		return "/"
	}
	return p
}
