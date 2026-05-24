package config

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"

	"github.com/fatih/color"
)

// Scanner describes how to install a required scanner.
type scannerDep struct {
	Name       string
	Binary     string
	BrewPkg    string // macOS/Linux via Homebrew
	PipPkg     string // via pip3 (fallback)
	InstallURL string // docs URL if we can't auto-install
}

var scannerDeps = []scannerDep{
	{
		Name:    "Semgrep",
		Binary:  "semgrep",
		PipPkg:  "semgrep",
		InstallURL: "https://semgrep.dev/docs/getting-started",
	},
	{
		Name:    "Trivy",
		Binary:  "trivy",
		BrewPkg: "trivy",
		InstallURL: "https://aquasecurity.github.io/trivy/latest/getting-started/installation",
	},
	{
		Name:    "Gitleaks",
		Binary:  "gitleaks",
		BrewPkg: "gitleaks",
		InstallURL: "https://github.com/gitleaks/gitleaks#installing",
	},
	{
		Name:    "Checkov",
		Binary:  "checkov",
		PipPkg:  "checkov",
		InstallURL: "https://www.checkov.io/1.Welcome/Quick%20Start.html",
	},
	{
		Name:    "Syft",
		Binary:  "syft",
		BrewPkg: "syft",
		InstallURL: "https://github.com/anchore/syft#installation",
	},
}

// EnsureScanners checks which scanners are missing and installs them.
// This is called automatically before the first scan.
func EnsureScanners() error {
	missing := []scannerDep{}
	for _, dep := range scannerDeps {
		if _, err := exec.LookPath(dep.Binary); err != nil {
			missing = append(missing, dep)
		}
	}

	if len(missing) == 0 {
		return nil
	}

	fmt.Printf("Installing %d missing scanner(s)...\n\n", len(missing))

	hasBrew := hasBrew()
	hasPip := hasPip()

	for _, dep := range missing {
		fmt.Printf("  Installing %s... ", dep.Name)

		var err error
		if dep.BrewPkg != "" && hasBrew {
			err = runQuiet("brew", "install", dep.BrewPkg)
		} else if dep.PipPkg != "" && hasPip {
			err = runQuiet("pip3", "install", dep.PipPkg)
		} else {
			color.Yellow("skipped\n")
			fmt.Printf("    Install manually: %s\n", dep.InstallURL)
			continue
		}

		if err != nil {
			color.Red("failed\n")
			fmt.Printf("    Install manually: %s\n", dep.InstallURL)
		} else {
			color.Green("done\n")
		}
	}

	fmt.Println()
	return nil
}

// RunInit is the full init flow — called by `trojan init`.
func RunInit(projectPath string) error {
	fmt.Println("Setting up Trojan...\n")

	// Install missing scanners
	if err := EnsureScanners(); err != nil {
		return err
	}

	// Add .trojan/ to .gitignore
	if err := ensureGitignore(projectPath); err != nil {
		color.Yellow("Warning: could not update .gitignore: %s\n", err)
	}

	color.Green("Trojan is ready. Run `trojan scan` to scan your project.\n")
	return nil
}

func ensureGitignore(projectPath string) error {
	gitignorePath := projectPath + "/.gitignore"
	entry := "\n# Trojan scan results\n.trojan/\n"

	f, err := os.OpenFile(gitignorePath, os.O_APPEND|os.O_CREATE|os.O_RDWR, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	// Check if already present
	content, _ := os.ReadFile(gitignorePath)
	if contains(string(content), ".trojan/") {
		return nil
	}

	_, err = f.WriteString(entry)
	return err
}

func hasBrew() bool {
	_, err := exec.LookPath("brew")
	return err == nil
}

func hasPip() bool {
	_, err := exec.LookPath("pip3")
	return err == nil
}

func runQuiet(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdout = nil
	cmd.Stderr = nil
	return cmd.Run()
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsStr(s, substr))
}

func containsStr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// Platform returns the current OS for informational purposes.
func Platform() string {
	return runtime.GOOS
}
