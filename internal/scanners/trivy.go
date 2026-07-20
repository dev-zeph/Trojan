package scanners

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"sync"

	"github.com/dev-zeph/trojan/internal/normalizer"
)

// Trivy implements the Scanner interface for SCA (dependency vulnerability scanning).
// It uses pointer receivers so it can cache the extracted package list for the caller
// to retrieve after Run() completes.
type Trivy struct {
	mu       sync.Mutex
	packages []normalizer.Package
}

func (t *Trivy) Name() string     { return "trivy" }
func (t *Trivy) Category() string { return "sca" }

func (t *Trivy) IsAvailable() bool {
	return IsInstalled("trivy")
}

func (t *Trivy) Run(projectPath string) ([]normalizer.Finding, error) {
	if !t.IsAvailable() {
		return nil, fmt.Errorf("trivy not found: run 'trojan init' to install it")
	}

	cmd := exec.Command(ManagedBinary("trivy"), "fs", "--format", "json", "--quiet", projectPath)
	output, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 1 {
			// exit code 1 just means findings were found — not a real error
		} else {
			return nil, fmt.Errorf("trivy failed: %w", err)
		}
	}

	var result trivyOutput
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, fmt.Errorf("failed to parse trivy output: %w", err)
	}

	// Build findings (CVE list)
	findings := []normalizer.Finding{}
	idx := 0
	for _, res := range result.Results {
		for _, vuln := range res.Vulnerabilities {
			findings = append(findings, normalizer.Finding{
				ID:         fmt.Sprintf("trivy-%d", idx),
				Scanner:    t.Name(),
				Category:   t.Category(),
				Severity:   normalizeTrivySeverity(vuln.Severity),
				Title:      fmt.Sprintf("%s in %s", vuln.VulnerabilityID, vuln.PkgName),
				RawMessage: vuln.Description,
				FilePath:   res.Target,
				LineNumber: 0,
				RuleID:     vuln.VulnerabilityID,
				Status:     normalizer.StatusOpen,
			})
			idx++
		}
	}

	// Build and cache the package list for the dashboard
	pkgs := buildPackages(result)
	t.mu.Lock()
	t.packages = pkgs
	t.mu.Unlock()

	return findings, nil
}

// Packages returns the full dependency list extracted during the last Run() call.
// Safe to call concurrently.
func (t *Trivy) Packages() []normalizer.Package {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.packages
}

// buildPackages constructs a deduplicated Package slice from raw trivy output.
// It merges the full package inventory (Results[].Packages) with vulnerability
// data (Results[].Vulnerabilities) so every package appears exactly once,
// with its CVE count and highest severity pre-computed.
func buildPackages(output trivyOutput) []normalizer.Package {
	type pkgKey struct{ name, version, eco string }

	pkgMap := map[pkgKey]*normalizer.Package{}
	var order []pkgKey

	for _, res := range output.Results {
		eco := trivyEcosystem(res.Type)

		// Pass 1 — register every package in the inventory (including safe ones).
		for _, p := range res.Packages {
			if p.Name == "" {
				continue
			}
			key := pkgKey{p.Name, p.Version, eco}
			if _, exists := pkgMap[key]; !exists {
				pkg := normalizer.Package{
					Name:      p.Name,
					Version:   p.Version,
					Ecosystem: eco,
					Direct:    !p.Indirect,
				}
				pkgMap[key] = &pkg
				order = append(order, key)
			}
		}

		// Pass 2 — attach CVE advisories to their packages.
		for _, v := range res.Vulnerabilities {
			if v.PkgName == "" {
				continue
			}
			key := pkgKey{v.PkgName, v.InstalledVersion, eco}
			if _, exists := pkgMap[key]; !exists {
				// Package wasn't in the inventory (older trivy) — add it now.
				pkg := normalizer.Package{
					Name:      v.PkgName,
					Version:   v.InstalledVersion,
					Ecosystem: eco,
					Direct:    true,
				}
				pkgMap[key] = &pkg
				order = append(order, key)
			}

			pd := pkgMap[key]
			sev := normalizeTrivySeverity(v.Severity)
			pd.CVECount++
			pd.Advisories = append(pd.Advisories, normalizer.PackageAdvisory{
				ID:         v.VulnerabilityID,
				Severity:   sev,
				Summary:    truncateDesc(v.Description, 220),
				FixVersion: v.FixedVersion,
			})

			// Track the earliest fix version (first non-empty one we see).
			if v.FixedVersion != "" && pd.FixVersion == "" {
				pd.FixVersion = v.FixedVersion
			}

			// Track highest severity across all advisories for this package.
			if pd.HighestSeverity == "" || trivySeverityRank(sev) > trivySeverityRank(pd.HighestSeverity) {
				pd.HighestSeverity = sev
			}
		}
	}

	pkgs := make([]normalizer.Package, 0, len(order))
	for _, key := range order {
		pkgs = append(pkgs, *pkgMap[key])
	}
	return pkgs
}

// trivyEcosystem maps Trivy's package type strings to OSV/ecosystem names.
func trivyEcosystem(pkgType string) string {
	switch strings.ToLower(pkgType) {
	case "npm", "yarn", "pnpm":
		return "npm"
	case "pip", "pipenv", "poetry":
		return "PyPI"
	case "gomod":
		return "Go"
	case "maven", "gradle":
		return "Maven"
	case "cargo":
		return "crates.io"
	case "composer":
		return "Packagist"
	case "gem":
		return "RubyGems"
	case "nuget":
		return "NuGet"
	default:
		if pkgType == "" {
			return "unknown"
		}
		return pkgType
	}
}

func trivySeverityRank(s normalizer.Severity) int {
	switch s {
	case normalizer.SeverityCritical:
		return 4
	case normalizer.SeverityHigh:
		return 3
	case normalizer.SeverityMedium:
		return 2
	case normalizer.SeverityLow:
		return 1
	default:
		return 0
	}
}

func truncateDesc(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// trivyOutput is the JSON schema returned by `trivy fs --format json`.
type trivyOutput struct {
	Results []struct {
		Target string `json:"Target"`
		Type   string `json:"Type"` // "npm", "gomod", "pip", etc.
		Vulnerabilities []struct {
			VulnerabilityID  string `json:"VulnerabilityID"`
			PkgName          string `json:"PkgName"`
			InstalledVersion string `json:"InstalledVersion"`
			FixedVersion     string `json:"FixedVersion"`
			Severity         string `json:"Severity"`
			Description      string `json:"Description"`
		} `json:"Vulnerabilities"`
		Packages []struct {
			Name     string `json:"Name"`
			Version  string `json:"Version"`
			Indirect bool   `json:"Indirect"`
		} `json:"Packages"`
	} `json:"Results"`
}

func normalizeTrivySeverity(s string) normalizer.Severity {
	switch strings.ToUpper(s) {
	case "CRITICAL":
		return normalizer.SeverityCritical
	case "HIGH":
		return normalizer.SeverityHigh
	case "MEDIUM":
		return normalizer.SeverityMedium
	case "LOW":
		return normalizer.SeverityLow
	default:
		return normalizer.SeverityInfo
	}
}
