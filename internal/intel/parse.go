package intel

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// maxWalkDepth bounds how deep below the project root lockfiles are searched
// (monorepos keep apps/* and packages/* a few levels down).
const maxWalkDepth = 6

// skipDirs are never descended into: installed trees, VCS, Trojan's own
// folder, virtualenvs and build output.
var skipDirs = map[string]bool{
	"node_modules": true, ".git": true, ".trojan": true, "vendor": true,
	"venv": true, ".venv": true, "dist": true, "build": true,
	".next": true, ".nuxt": true, ".svelte-kit": true, ".turbo": true,
	".tox": true, "__pycache__": true, "site-packages": true, ".cache": true,
	".yarn": true, ".pnpm-store": true, "coverage": true,
}

var requirementsName = regexp.MustCompile(`(?i)^requirements.*\.txt$`)

// lockfileParser parses one lockfile. rel is its slash path relative to the
// project root (stamped into Package.Lockfile).
type lockfileParser func(path, rel string) ([]Package, error)

// parserFor returns the parser for a lockfile base name, or nil.
func parserFor(base string) lockfileParser {
	switch base {
	case "package-lock.json", "npm-shrinkwrap.json":
		return parseNPMLock
	case "pnpm-lock.yaml":
		return parsePNPMLock
	case "yarn.lock":
		return parseYarnLock
	case "bun.lock":
		return parseBunLock
	case "poetry.lock":
		return parsePoetryLock
	case "uv.lock":
		return parseUVLock
	case "Pipfile.lock":
		return parsePipfileLock
	}
	if requirementsName.MatchString(base) {
		return parseRequirements
	}
	return nil
}

// IsLockfile reports whether a file name is one ParseProject understands.
func IsLockfile(name string) bool { return parserFor(filepath.Base(name)) != nil }

// ParseProject walks projectPath (skipping node_modules, .git, .trojan,
// vendor, virtualenvs and build output, at most 6 levels deep) and parses
// every supported lockfile into a deduplicated, sorted inventory. It returns
// the packages and the lockfiles that parsed (relative, slash-separated).
// A lockfile that fails to parse is skipped; use ParseProjectWithWarnings to
// see why.
func ParseProject(projectPath string) ([]Package, []string, error) {
	pkgs, files, _, err := ParseProjectWithWarnings(projectPath)
	return pkgs, files, err
}

// ParseProjectWithWarnings is ParseProject plus one warning per lockfile that
// could not be parsed. The error is non-nil only when projectPath itself can't
// be read.
func ParseProjectWithWarnings(projectPath string) ([]Package, []string, []string, error) {
	root, err := filepath.Abs(projectPath)
	if err != nil {
		return nil, nil, nil, err
	}
	st, err := os.Stat(root)
	if err != nil {
		return nil, nil, nil, err
	}
	if !st.IsDir() {
		return nil, nil, nil, fmt.Errorf("%s is not a directory", projectPath)
	}

	var found []string
	walkErr := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			if path == root {
				return err
			}
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			if path == root {
				return nil
			}
			if skipDirs[d.Name()] {
				return fs.SkipDir
			}
			rel, _ := filepath.Rel(root, path)
			if strings.Count(rel, string(filepath.Separator))+1 > maxWalkDepth {
				return fs.SkipDir
			}
			return nil
		}
		if d.Type().IsRegular() && parserFor(d.Name()) != nil {
			found = append(found, path)
		}
		return nil
	})
	if walkErr != nil {
		return nil, nil, nil, walkErr
	}
	sort.Strings(found)

	var all []Package
	var files, warnings []string
	for _, path := range found {
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		pkgs, err := parserFor(filepath.Base(path))(path, rel)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("%s: %v", rel, err))
			continue
		}
		files = append(files, rel)
		all = append(all, pkgs...)
	}
	return Dedupe(all), files, warnings, nil
}

// ParseLockfile parses a single lockfile. Package.Lockfile is set to the
// file's base name. Useful for re-checking one lockfile after an upgrade.
func ParseLockfile(path string) ([]Package, error) {
	p := parserFor(filepath.Base(path))
	if p == nil {
		return nil, errors.New("unsupported lockfile: " + filepath.Base(path))
	}
	pkgs, err := p(path, filepath.Base(path))
	if err != nil {
		return nil, err
	}
	return Dedupe(pkgs), nil
}

// Dedupe merges packages with the same (ecosystem, name, version): Direct is
// OR'd and Lockfiles collects every source. Distinct versions of one package
// are all kept. Output is sorted by ecosystem, name, version.
func Dedupe(pkgs []Package) []Package {
	idx := map[string]int{}
	var out []Package
	for _, p := range pkgs {
		if p.Lockfile != "" && len(p.Lockfiles) == 0 {
			p.Lockfiles = []string{p.Lockfile}
		}
		k := p.key()
		if i, ok := idx[k]; ok {
			q := &out[i]
			q.Direct = q.Direct || p.Direct
			for _, lf := range p.Lockfiles {
				if !contains(q.Lockfiles, lf) {
					q.Lockfiles = append(q.Lockfiles, lf)
				}
			}
			continue
		}
		idx[k] = len(out)
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Ecosystem != b.Ecosystem {
			return a.Ecosystem < b.Ecosystem
		}
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		return a.Version < b.Version
	})
	return out
}

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

// newPkg builds a Package, validating and normalizing the version for the
// ecosystem. ok=false for non-registry versions (git URLs, file:, link:,
// workspace:) that advisories can't be matched against.
func newPkg(eco, name, version, rel string, direct bool) (Package, bool) {
	name = strings.TrimSpace(name)
	version = strings.TrimSpace(version)
	if name == "" || version == "" {
		return Package{}, false
	}
	switch eco {
	case EcosystemNPM:
		version = strings.TrimPrefix(version, "v")
		if _, err := parseSemver(version); err != nil {
			return Package{}, false
		}
	case EcosystemPyPI:
		name = NormalizePyPIName(name)
		if _, err := parsePEP440(version); err != nil {
			return Package{}, false
		}
	}
	return Package{Ecosystem: eco, Name: name, Version: version, Lockfile: rel, Direct: direct}, true
}
