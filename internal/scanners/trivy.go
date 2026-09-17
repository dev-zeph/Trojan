package scanners

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
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

	// --exit-code 1 makes trivy's exit code an unambiguous contract: 0 means
	// "ran clean, nothing found", 1 means "vulnerabilities were found" (this
	// flag is opt-in and defaults to 0, so without it exit 1 instead meant a
	// FATAL error, which the old code below wrongly treated as "findings
	// found" and silently swallowed).
	cmd := exec.Command(ManagedBinary("trivy"), "fs", "--format", "json", "--quiet", "--exit-code", "1", projectPath)
	cmd.Env = trivyEnv()
	output, err := cmd.Output()

	result, err := parseTrivyOutput(output, err)
	if err != nil {
		return nil, err
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

// parseTrivyOutput validates a trivy invocation's raw stdout/error and returns
// the parsed JSON report, translating exec/parse failures into diagnostic
// errors a developer can act on. Split out from Run so this contract — exit
// code semantics, stderr propagation, and the empty-stdout guard — can be
// unit tested without shelling out to a real trivy binary.
func parseTrivyOutput(output []byte, runErr error) (trivyOutput, error) {
	if runErr != nil {
		exitErr, isExitErr := runErr.(*exec.ExitError)
		if isExitErr && exitErr.ExitCode() == 1 {
			// With --exit-code 1 set, exit 1 unambiguously means "vulnerabilities
			// were found" — trivy still wrote a full JSON report to stdout.
		} else {
			// Any other non-zero exit is a real failure (e.g. the DB download
			// hitting a docker-credential-helper error). Surface trivy's own
			// stderr — cmd.Output() populates ExitError.Stderr — instead of
			// swallowing it, since a silently-empty dependency tab is worse
			// than a loud failure for a security tool.
			if isExitErr {
				if stderr := strings.TrimSpace(string(exitErr.Stderr)); stderr != "" {
					return trivyOutput{}, fmt.Errorf("trivy failed: %s", stderr)
				}
			}
			return trivyOutput{}, fmt.Errorf("trivy failed: %w", runErr)
		}
	}

	if len(strings.TrimSpace(string(output))) == 0 {
		return trivyOutput{}, fmt.Errorf("trivy produced no output: the scan likely failed before it could write a report. Run 'trivy fs <path>' directly to see the underlying error")
	}

	var result trivyOutput
	if err := json.Unmarshal(output, &result); err != nil {
		return trivyOutput{}, fmt.Errorf("failed to parse trivy output: %w", err)
	}
	return result, nil
}

// trivyEnv returns the environment for the trivy subprocess. It scopes
// DOCKER_CONFIG to an isolated, credential-free directory so trivy's
// vulnerability-DB download (an OCI artifact pull) never invokes a docker
// credential helper. Without this, any machine whose ~/.docker/config.json
// sets "credsStore" to a helper that isn't on PATH (e.g. Docker Desktop's
// docker-credential-desktop, commonly missing from PATH for GUI-launched
// apps) causes trivy to exit fatally before it scans anything. This only
// affects trivy's own subprocess env — the user's real docker config on
// disk is never touched.
func trivyEnv() []string {
	env := os.Environ()
	if dir, err := isolatedDockerConfigDir(); err == nil {
		env = append(env, "DOCKER_CONFIG="+dir)
	}
	return env
}

// isolatedDockerConfigDir returns (creating if needed) ~/.trojan/trivy-dockerconfig,
// an empty directory with no config.json — i.e. no credsStore, no auths — so
// registry/OCI pulls made under it fall back to anonymous access.
func isolatedDockerConfigDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(home, ".trojan", "trivy-dockerconfig")
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", err
	}
	return dir, nil
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
