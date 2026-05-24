package scanners

import (
	"os"
	"path/filepath"
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
}

// DetectProject inspects the project path and returns what it found.
func DetectProject(projectPath string) ProjectType {
	p := ProjectType{}

	indicators := map[string]*bool{
		"package.json":      &p.HasNode,
		"requirements.txt":  &p.HasPython,
		"pyproject.toml":    &p.HasPython,
		"go.mod":            &p.HasGo,
		"Gemfile":           &p.HasRuby,
		"pom.xml":           &p.HasJava,
		"build.gradle":      &p.HasJava,
		"main.tf":           &p.HasIaC,
		"Dockerfile":        &p.HasIaC,
		".git":              &p.HasGitHistory,
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

	return p
}

// RelevantScanners filters the scanner list based on what the project contains.
func RelevantScanners(all []Scanner, p ProjectType) []Scanner {
	relevant := []Scanner{}
	for _, s := range all {
		switch s.Name() {
		case "semgrep":
			relevant = append(relevant, s) // always run SAST
		case "trivy":
			relevant = append(relevant, s) // always run SCA
		case "gitleaks":
			if p.HasGitHistory {
				relevant = append(relevant, s)
			}
		case "checkov":
			if p.HasIaC {
				relevant = append(relevant, s)
			}
		case "syft":
			relevant = append(relevant, s) // always generate SBOM
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
