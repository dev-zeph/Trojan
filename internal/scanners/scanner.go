package scanners

import "github.com/dev-zeph/trojan/internal/normalizer"

// Scanner is the interface every scanner must implement.
// This ensures Semgrep, Trivy, Gitleaks, Checkov, and Syft
// all plug into the same pipeline.
type Scanner interface {
	// Name returns the scanner's identifier (e.g. "semgrep", "trivy")
	Name() string

	// Category returns the type of scanning (e.g. "sast", "sca", "secrets", "iac", "sbom")
	Category() string

	// Run executes the scanner against the given project path
	// and returns normalized findings.
	Run(projectPath string) ([]normalizer.Finding, error)

	// IsAvailable checks whether the scanner binary is installed.
	IsAvailable() bool
}
