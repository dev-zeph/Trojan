package scanners

import (
	"encoding/json"
	"fmt"
	"os/exec"

	"github.com/dev-zeph/trojan/internal/normalizer"
)

// Syft implements the Scanner interface for SBOM generation.
// Unlike the other scanners, Syft generates an inventory rather than findings.
// We return one informational finding per artifact as a summary.
type Syft struct{}

func (s Syft) Name() string     { return "syft" }
func (s Syft) Category() string { return "sbom" }

func (s Syft) IsAvailable() bool {
	_, err := exec.LookPath("syft")
	return err == nil
}

func (s Syft) Run(projectPath string) ([]normalizer.Finding, error) {
	if !s.IsAvailable() {
		return nil, fmt.Errorf("syft not found: run 'trojan init' to install it")
	}

	cmd := exec.Command("syft", projectPath, "-o", "syft-json")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("syft failed: %w", err)
	}

	var result syftOutput
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, fmt.Errorf("failed to parse syft output: %w", err)
	}

	// Syft produces an SBOM, not vulnerabilities.
	// Return a single informational finding summarizing the inventory.
	if len(result.Artifacts) == 0 {
		return []normalizer.Finding{}, nil
	}

	findings := []normalizer.Finding{
		{
			ID:         "syft-0",
			Scanner:    s.Name(),
			Category:   s.Category(),
			Severity:   normalizer.SeverityInfo,
			Title:      fmt.Sprintf("SBOM: %d packages inventoried", len(result.Artifacts)),
			RawMessage: fmt.Sprintf("Syft identified %d artifacts. Full SBOM saved to .trojan/sbom.json.", len(result.Artifacts)),
			FilePath:   projectPath,
			Status:     normalizer.StatusOpen,
		},
	}

	return findings, nil
}

type syftOutput struct {
	Artifacts []struct {
		Name    string `json:"name"`
		Version string `json:"version"`
		Type    string `json:"type"`
	} `json:"artifacts"`
}
