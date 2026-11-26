package scanners

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// envWalkSkipDirs are directories we do not walk when looking for local
// .env files to mention in the scan summary.
var envWalkSkipDirs = map[string]bool{
	"node_modules": true, "vendor": true, "bower_components": true,
	".git": true, ".trojan": true, ".svn": true, ".hg": true,
	"dist": true, "build": true, "out": true, ".next": true,
	"target": true, "__pycache__": true, ".venv": true, "venv": true,
}

// ProjectSkippedLocalEnv reports whether a local-only .env (or .env.*)
// was left out of the scan. This is deliberate: in a git work tree a
// gitignored .env holds local secrets; outside git, unsuffixed .env
// files are treated the same way. Shared copies (.env.example, .sample,
// .template, .dist) are still scanned.
func ProjectSkippedLocalEnv(projectPath string) bool {
	return len(SkippedLocalEnvFiles(projectPath)) > 0
}

// SkippedLocalEnvFiles returns project-relative paths of local-only .env
// files that the secrets scan does not report. The list is empty when
// there is no such file, or when every .env is tracked (not gitignored).
func SkippedLocalEnvFiles(projectPath string) []string {
	if projectPath == "" || strings.Contains(projectPath, "://") {
		return nil
	}
	files := listLocalEnvFiles(projectPath)
	if len(files) == 0 {
		return nil
	}
	results := make([]gitleaksResult, len(files))
	for i, f := range files {
		results[i] = gitleaksResult{File: f}
	}
	ignored, ok := gitIgnoredFiles(projectPath, results)
	if !ok {
		// Not a git work tree (or git cannot answer): the same rule as
		// dropLocalOnlyFiles treats these files as local-only.
		return files
	}
	var out []string
	for _, f := range files {
		if ignored[f] {
			out = append(out, f)
		}
	}
	return out
}

func listLocalEnvFiles(projectPath string) []string {
	info, err := os.Stat(projectPath)
	if err != nil || !info.IsDir() {
		return nil
	}
	var out []string
	_ = filepath.WalkDir(projectPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		name := d.Name()
		if d.IsDir() {
			if envWalkSkipDirs[name] {
				return filepath.SkipDir
			}
			return nil
		}
		if !isLocalEnvFile(name) {
			return nil
		}
		rel, err := filepath.Rel(projectPath, path)
		if err != nil {
			return nil
		}
		out = append(out, filepath.ToSlash(rel))
		return nil
	})
	return out
}
