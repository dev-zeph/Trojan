package config

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/fatih/color"
)

const githubReleaseURL = "https://api.github.com/repos/dev-zeph/Trojan/releases/latest"

type githubRelease struct {
	TagName string `json:"tag_name"`
	HTMLURL string `json:"html_url"`
	Body    string `json:"body"`
}

// CheckForUpdate fetches the latest release from GitHub and compares it
// to the current version. Returns (latestVersion, updateAvailable, error).
func CheckForUpdate(currentVersion string) (string, bool, error) {
	client := &http.Client{Timeout: 5 * time.Second}

	req, err := http.NewRequest("GET", githubReleaseURL, nil)
	if err != nil {
		return "", false, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "trojan-cli/"+currentVersion)

	resp, err := client.Do(req)
	if err != nil {
		return "", false, fmt.Errorf("could not reach GitHub: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", false, fmt.Errorf("release check returned status %d", resp.StatusCode)
	}

	var release githubRelease
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return "", false, fmt.Errorf("could not parse release info: %w", err)
	}

	latest := release.TagName
	if latest == "" {
		return "", false, nil
	}
	// Strip leading 'v' for comparison
	if latest[0] == 'v' {
		latest = latest[1:]
	}

	current := currentVersion
	if len(current) > 0 && current[0] == 'v' {
		current = current[1:]
	}

	return latest, latest != current, nil
}

// NotifyIfOutdated silently checks for updates and prints a notice if one is available.
// Designed to be called in the background before a scan.
func NotifyIfOutdated(currentVersion string) {
	latest, available, err := CheckForUpdate(currentVersion)
	if err != nil || !available {
		return
	}

	fmt.Println()
	color.Yellow("  Update available: v%s → v%s", currentVersion, latest)
	fmt.Printf("  Run `trojan update` or visit https://github.com/dev-zeph/Trojan/releases\n\n")
}

// RunUpdate checks for a new version and prints instructions.
// Actual binary replacement is handled by the install script.
func RunUpdate(currentVersion string) error {
	fmt.Printf("Current version: v%s\n", currentVersion)
	fmt.Printf("Checking for updates...\n\n")

	latest, available, err := CheckForUpdate(currentVersion)
	if err != nil {
		return fmt.Errorf("could not check for updates: %w", err)
	}

	if !available {
		color.Green("You're up to date! (v%s)\n", currentVersion)
		return nil
	}

	color.Yellow("New version available: v%s\n\n", latest)
	fmt.Println("To update, run:")
	fmt.Println()
	fmt.Println("  brew upgrade trojan")
	fmt.Println()
	fmt.Println("  — or —")
	fmt.Println()
	fmt.Println("  curl -fsSL https://trojan.dev/install.sh | sh")
	fmt.Println()

	return nil
}
