package normalizer

import (
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// ── Website tests (DAST / pen tests) ─────────────────────────────────────────
//
// A website test isn't tied to a project folder, so its results are kept in a
// per-site folder under ~/.trojan/website-tests/<site>/.trojan/scans/, the same
// layout as a project's scans. The MCP server reads them from there, so an AI
// tool can see pen-test findings whichever project it is open in.

var unsafeSiteChars = regexp.MustCompile(`[^a-zA-Z0-9.-]+`)

// WebsiteTestsDir is the folder holding every site's results.
func WebsiteTestsDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".trojan", "website-tests"), nil
}

// WebsiteDir is the folder for one site, keyed by host and port
// (https://app.example.com/x → app.example.com, http://localhost:3000 → localhost_3000).
func WebsiteDir(targetURL string) (string, error) {
	root, err := WebsiteTestsDir()
	if err != nil {
		return "", err
	}
	host := targetURL
	if u, err := url.Parse(targetURL); err == nil && u.Host != "" {
		host = u.Host
	}
	name := strings.Trim(unsafeSiteChars.ReplaceAllString(strings.ToLower(host), "_"), "_")
	if name == "" {
		name = "site"
	}
	return filepath.Join(root, name), nil
}

// SaveWebsiteTest stores a website test's findings in that site's folder.
func SaveWebsiteTest(targetURL string, findings []Finding) (*ScanResult, error) {
	dir, err := WebsiteDir(targetURL)
	if err != nil {
		return nil, err
	}
	return SaveScanResultAt(dir, targetURL, findings)
}

// WebsiteSiteDirs lists every tested site's folder, most recently tested first.
func WebsiteSiteDirs() []string {
	root, err := WebsiteTestsDir()
	if err != nil {
		return nil
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil
	}
	type site struct {
		dir    string
		latest string
	}
	var sites []site
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		dir := filepath.Join(root, e.Name())
		if latest := LatestScanFile(dir); latest != "" {
			sites = append(sites, site{dir, filepath.Base(latest)})
		}
	}
	sort.Slice(sites, func(i, j int) bool { return sites[i].latest > sites[j].latest })
	out := make([]string, len(sites))
	for i, s := range sites {
		out[i] = s.dir
	}
	return out
}

// LatestScanFile returns the newest <dir>/.trojan/scans/*.json, or "".
// File names are timestamps, so the newest sorts last.
func LatestScanFile(dir string) string {
	scansDir := filepath.Join(dir, ".trojan", "scans")
	entries, err := os.ReadDir(scansDir)
	if err != nil {
		return ""
	}
	var files []string
	for _, e := range entries {
		if !e.IsDir() && filepath.Ext(e.Name()) == ".json" {
			files = append(files, e.Name())
		}
	}
	if len(files) == 0 {
		return ""
	}
	sort.Strings(files)
	return filepath.Join(scansDir, files[len(files)-1])
}
