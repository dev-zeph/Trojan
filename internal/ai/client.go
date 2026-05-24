package ai

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/dev-zeph/trojan/internal/normalizer"
)

const (
	synthesizeURL = "https://dtmocojzvgsswjdsrmqr.supabase.co/functions/v1/synthesize"
	licenseURL    = "https://dtmocojzvgsswjdsrmqr.supabase.co/functions/v1/license"
)

// Synthesis holds the AI-generated explanation and fix steps for a finding.
type Synthesis struct {
	Simply  string   `json:"simply"`
	Actions []string `json:"actions"`
}

// LicenseInfo holds the user's subscription status fetched from the backend.
type LicenseInfo struct {
	IsPro              bool   `json:"isPro"`
	SubscriptionStatus string `json:"subscriptionStatus"`
	Email              string `json:"email"`
}

// FetchLicense checks the user's current subscription status against the backend.
func FetchLicense(accessToken string) (*LicenseInfo, error) {
	req, err := http.NewRequest(http.MethodGet, licenseURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("could not reach license server: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("license check failed (status %d)", resp.StatusCode)
	}

	var info LicenseInfo
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return nil, err
	}
	return &info, nil
}

// SynthesizeFinding calls the backend to get a plain-English explanation and
// fix steps for a finding. Results are cached locally to avoid repeat API calls.
func SynthesizeFinding(finding normalizer.Finding, accessToken string) (*Synthesis, error) {
	// Check local cache first
	if cached := loadFromCache(finding.RuleID, finding.Scanner); cached != nil {
		return cached, nil
	}

	payload := map[string]string{
		"ruleId":     finding.RuleID,
		"scanner":    finding.Scanner,
		"category":   finding.Category,
		"severity":   string(finding.Severity),
		"title":      finding.Title,
		"rawMessage": finding.RawMessage,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(http.MethodPost, synthesizeURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("synthesis request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("synthesis failed (status %d)", resp.StatusCode)
	}

	var synthesis Synthesis
	if err := json.NewDecoder(resp.Body).Decode(&synthesis); err != nil {
		return nil, err
	}

	saveToCache(finding.RuleID, finding.Scanner, &synthesis)
	return &synthesis, nil
}

// cachePath returns the local cache file path for a given rule+scanner pair.
func cachePath(ruleID, scanner string) string {
	home, _ := os.UserHomeDir()
	key := fmt.Sprintf("%s-%s.json", sanitize(ruleID), sanitize(scanner))
	return filepath.Join(home, ".trojan", "cache", key)
}

func loadFromCache(ruleID, scanner string) *Synthesis {
	data, err := os.ReadFile(cachePath(ruleID, scanner))
	if err != nil {
		return nil
	}
	var s Synthesis
	if err := json.Unmarshal(data, &s); err != nil {
		return nil
	}
	return &s
}

func saveToCache(ruleID, scanner string, s *Synthesis) {
	path := cachePath(ruleID, scanner)
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return
	}
	data, err := json.Marshal(s)
	if err != nil {
		return
	}
	os.WriteFile(path, data, 0600) //nolint:errcheck
}

// sanitize replaces characters that are invalid in filenames.
func sanitize(s string) string {
	result := make([]byte, len(s))
	for i := range s {
		c := s[i]
		if c == '/' || c == '\\' || c == ':' || c == '*' || c == '?' {
			result[i] = '_'
		} else {
			result[i] = c
		}
	}
	return string(result)
}
