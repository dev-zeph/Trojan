package scanners

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"sync"

	"github.com/dev-zeph/trojan/internal/normalizer"
)

// Syft implements the Scanner interface for SBOM generation.
// Unlike the other scanners, Syft generates an inventory rather than findings.
// It also extracts license data for each package, which is merged into the
// Package list built by Trivy.
type Syft struct {
	mu       sync.Mutex
	licenses map[string]string // "name@version" → license SPDX ID
}

func (s *Syft) Name() string     { return "syft" }
func (s *Syft) Category() string { return "sbom" }

func (s *Syft) IsAvailable() bool {
	return IsInstalled("syft")
}

func (s *Syft) Run(projectPath string) ([]normalizer.Finding, error) {
	if !s.IsAvailable() {
		return nil, fmt.Errorf("syft not found: run 'trojan init' to install it")
	}

	cmd := exec.Command(ManagedBinary("syft"), projectPath, "-o", "syft-json")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("syft failed: %w", err)
	}

	var result syftOutput
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, fmt.Errorf("failed to parse syft output: %w", err)
	}

	// Extract license data for each artifact.
	licMap := make(map[string]string, len(result.Artifacts))
	for _, a := range result.Artifacts {
		if len(a.Licenses) > 0 && a.Licenses[0].Value != "" {
			key := a.Name + "@" + a.Version
			licMap[key] = a.Licenses[0].Value
		}
	}
	s.mu.Lock()
	s.licenses = licMap
	s.mu.Unlock()

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

// Licenses returns the license map extracted during the last Run.
// Keys are "name@version", values are SPDX license identifiers.
func (s *Syft) Licenses() map[string]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.licenses
}

type syftOutput struct {
	Artifacts []struct {
		Name     string `json:"name"`
		Version  string `json:"version"`
		Type     string `json:"type"`
		Licenses []struct {
			Value          string `json:"value"`
			SpdxExpression string `json:"spdxExpression"`
		} `json:"licenses"`
	} `json:"artifacts"`
}
