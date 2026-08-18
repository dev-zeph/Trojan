package normalizer

import (
	"path/filepath"
	"strings"
)

// dropDirs are path segments (at any depth) whose contents are dependencies,
// build output, or test scaffolding — code that does not ship to production.
// A finding anywhere under one of these directories is dropped.
var dropDirs = map[string]bool{
	// Third-party dependencies (vendored/installed, not our code).
	"node_modules":     true,
	"vendor":           true,
	"bower_components": true,
	"site-packages":    true,
	".venv":            true,
	"venv":             true,
	// Build / generated output.
	"dist":   true,
	"build":  true,
	"out":    true,
	".next":  true,
	"target": true, // Java/Rust build dir
	"obj":    true,
	"__pycache__": true,
	// Test scaffolding.
	"test":       true,
	"tests":      true,
	"testdata":   true,
	"__tests__":  true,
	"__mocks__":  true,
	"spec":       true,
	// VCS.
	".git": true,
}

// FilterPaths drops findings located in non-shipping code — dependency,
// build-output, generated, and test files — and returns the survivors plus the
// number dropped. The dropped count is surfaced to the user (never a silent cut):
// these paths are excluded because a finding there is not exploitable in the
// shipped product, not because it doesn't exist.
//
// Findings with no file path (DAST/SCA/host-level) are always kept — there is
// no path to judge.
func FilterPaths(findings []Finding) (kept []Finding, dropped int) {
	kept = make([]Finding, 0, len(findings))
	for _, f := range findings {
		if f.FilePath != "" && IsNonShipping(f.FilePath) {
			dropped++
			continue
		}
		kept = append(kept, f)
	}
	return kept, dropped
}

// IsNonShipping reports whether a path is dependency, build, generated, or test
// code that should be excluded from results (and from the code index).
func IsNonShipping(path string) bool {
	p := filepath.ToSlash(filepath.Clean(path))
	for seg := range strings.SplitSeq(p, "/") {
		if dropDirs[seg] {
			return true
		}
	}
	return isGeneratedOrTestFile(filepath.Base(p))
}

// isGeneratedOrTestFile matches test and machine-generated files by name, for
// the common case where they sit beside production code rather than in a
// dedicated directory.
func isGeneratedOrTestFile(base string) bool {
	lower := strings.ToLower(base)

	// Generated code.
	if strings.HasSuffix(lower, ".min.js") ||
		strings.HasSuffix(lower, ".min.css") ||
		strings.HasSuffix(lower, ".pb.go") ||
		strings.HasSuffix(lower, "_pb2.py") ||
		strings.Contains(lower, ".generated.") ||
		strings.HasSuffix(lower, "_generated.go") {
		return true
	}

	// Test files.
	if strings.HasSuffix(lower, "_test.go") ||
		strings.HasPrefix(lower, "test_") || // Python: test_foo.py
		strings.HasSuffix(lower, "_test.py") {
		return true
	}
	// JS/TS: foo.test.ts / foo.spec.js and variants.
	for _, mid := range []string{".test.", ".spec."} {
		if strings.Contains(lower, mid) &&
			(strings.HasSuffix(lower, ".js") || strings.HasSuffix(lower, ".jsx") ||
				strings.HasSuffix(lower, ".ts") || strings.HasSuffix(lower, ".tsx")) {
			return true
		}
	}
	return false
}
