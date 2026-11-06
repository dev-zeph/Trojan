package scanners

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/dev-zeph/trojan/internal/graph"
	"github.com/dev-zeph/trojan/internal/normalizer"
)

// ProjectType holds what we detected about the project.
type ProjectType struct {
	HasNode       bool // package.json found
	HasPython     bool // requirements.txt or pyproject.toml found
	HasGo         bool // go.mod found
	HasRuby       bool // Gemfile found
	HasJava       bool // pom.xml or build.gradle found
	HasIaC        bool // Terraform, Dockerfile, or K8s manifests found
	HasGitHistory bool // .git directory found
	HasPHP        bool // composer.json/composer.lock at the root, or any .php source file
	HasComposer   bool // composer.json or composer.lock at the project root

	// UngraphedLangs lists languages found in the project's own source that
	// Trojan's code-graph checks (the "trojan" scanner) don't parse, in a
	// fixed order (e.g. ["PHP"]). Those files are still covered by the rule
	// scanners (Semgrep, Bearer); see CoverageNote.
	UngraphedLangs []string
	// NoGraphSource is true when the source walk finished and found no file
	// the code-graph checks can parse (Go, JS/TS, Python). The "trojan"
	// scanner is then skipped rather than reporting a misleading clean 0.
	// The zero value (false) keeps the scanner, so callers that build a
	// ProjectType by hand see the old behavior.
	NoGraphSource bool
}

// DetectProject inspects the project path and returns what it found.
func DetectProject(projectPath string) ProjectType {
	p := ProjectType{}

	indicators := map[string]*bool{
		"package.json":     &p.HasNode,
		"requirements.txt": &p.HasPython,
		"pyproject.toml":   &p.HasPython,
		"go.mod":           &p.HasGo,
		"Gemfile":          &p.HasRuby,
		"pom.xml":          &p.HasJava,
		"build.gradle":     &p.HasJava,
		"main.tf":          &p.HasIaC,
		"Dockerfile":       &p.HasIaC,
		".git":             &p.HasGitHistory,
		"composer.json":    &p.HasComposer,
		"composer.lock":    &p.HasComposer,
	}

	for file, flag := range indicators {
		if exists(filepath.Join(projectPath, file)) {
			*flag = true
		}
	}

	// Also check for K8s manifests (*.yaml files with "kind:" inside)
	if !p.HasIaC {
		p.HasIaC = hasKubernetesManifests(projectPath)
	}

	langs := walkSourceLangs(projectPath)
	p.HasPHP = p.HasComposer || langs.found["PHP"]
	for _, l := range ungraphedLangOrder {
		if langs.found[l] {
			p.UngraphedLangs = append(p.UngraphedLangs, l)
		}
	}
	p.NoGraphSource = langs.complete && !langs.graphSource

	return p
}

// ungraphedLangOrder is the report order of languages the code-graph checks
// don't parse, by the label CoverageNote uses.
var ungraphedLangOrder = []string{"PHP", "Ruby", "Java", "C#"}

var ungraphedLangExts = map[string]string{
	".php":   "PHP",
	".phtml": "PHP",
	".rb":    "Ruby",
	".java":  "Java",
	".kt":    "Java",
	".cs":    "C#",
}

// maxDetectWalkEntries bounds the source-language walk on huge trees. Past it
// the walk stops and reports what it saw so far, marked incomplete (so a
// missing graph language is never assumed).
const maxDetectWalkEntries = 200000

type sourceLangs struct {
	found       map[string]bool // ungraphed language label -> present
	graphSource bool            // at least one file the code graph parses
	complete    bool            // walk finished within the entry budget
}

// walkSourceLangs walks the project's own source (skipping dependency, build,
// test and dot directories, the same pruning the code index uses) and records
// which languages are present.
func walkSourceLangs(root string) sourceLangs {
	out := sourceLangs{found: map[string]bool{}}
	if info, err := os.Stat(root); err != nil || !info.IsDir() {
		return out
	}
	entries := 0
	truncated := false
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // unreadable entry: skip it, keep walking
		}
		entries++
		if entries > maxDetectWalkEntries {
			truncated = true
			return fs.SkipAll
		}
		rel, rerr := filepath.Rel(root, path)
		if rerr != nil {
			rel = path
		}
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			if rel == "." {
				return nil
			}
			if strings.HasPrefix(d.Name(), ".") || normalizer.IsNonShipping(rel) {
				return fs.SkipDir
			}
			return nil
		}
		if normalizer.IsNonShipping(rel) {
			return nil
		}
		if graph.BatchOf(path) != "" {
			out.graphSource = true
		}
		if l, ok := ungraphedLangExts[strings.ToLower(filepath.Ext(path))]; ok {
			out.found[l] = true
		}
		return nil
	})
	out.complete = err == nil && !truncated
	return out
}

// CoverageNote is a plain note for the scan result when the project contains
// code in a language Trojan's code-graph checks don't parse yet. Those files
// are still checked by the rule scanners; the note says so, so an empty result
// from the graph checks is never read as "this code is clean". Returns "" when
// every language present is covered.
func CoverageNote(p ProjectType) string {
	langs := p.UngraphedLangs
	switch len(langs) {
	case 0:
		return ""
	case 1:
		l := langs[0]
		return l + ": Trojan checks " + l + " with pattern rules. Deeper code-flow analysis for " + l + " is coming."
	}
	list := strings.Join(langs[:len(langs)-1], ", ") + " and " + langs[len(langs)-1]
	return list + ": Trojan checks these languages with pattern rules. Deeper code-flow analysis for them is coming."
}

// RelevantScanners filters the scanner list based on what the project contains.
func RelevantScanners(all []Scanner, p ProjectType) []Scanner {
	relevant := []Scanner{}
	for _, s := range all {
		switch s.Name() {
		case "semgrep":
			// Always run SAST, with Trojan's own rules. PHP projects also get
			// the PHP registry packs (see Semgrep.PHP).
			if sg, ok := s.(Semgrep); ok && p.HasPHP {
				sg.PHP = true
				s = sg
			}
			relevant = append(relevant, s)
		case "bearer":
			relevant = append(relevant, s) // always run SAST
		case "trivy":
			relevant = append(relevant, s) // always run SCA
		case "gitleaks":
			// Always scan for secrets. Gitleaks reads the files on disk and,
			// when there is a .git folder, the commit history too. Gating on
			// .git used to skip secrets scanning entirely for folders that
			// were never committed.
			relevant = append(relevant, s)
		case "checkov":
			if p.HasIaC {
				relevant = append(relevant, s)
			}
		case "syft":
			relevant = append(relevant, s) // always generate SBOM
		case "trojan":
			// Trojan's own code-graph checks, no binary needed. Skipped when
			// the project has no source the graph can parse (e.g. a PHP-only
			// app): a 0 from it would read as "clean" when nothing was checked.
			if !p.NoGraphSource {
				relevant = append(relevant, s)
			}
		}
	}
	return relevant
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func hasKubernetesManifests(projectPath string) bool {
	found := false
	filepath.Walk(projectPath, func(path string, info os.FileInfo, err error) error {
		if err != nil || found {
			return nil
		}
		if !info.IsDir() && (filepath.Ext(path) == ".yaml" || filepath.Ext(path) == ".yml") {
			data, err := os.ReadFile(path)
			if err == nil && containsKind(string(data)) {
				found = true
			}
		}
		return nil
	})
	return found
}

func containsKind(content string) bool {
	// Simple check for Kubernetes manifest marker
	for i := 0; i < len(content)-5; i++ {
		if content[i:i+5] == "kind:" {
			return true
		}
	}
	return false
}
