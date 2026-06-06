package dast

import (
	"bytes"
	"crypto/md5"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"time"
)

const (
	dastTemplatesURL = "https://dtmocojzvgsswjdsrmqr.supabase.co/functions/v1/dast-templates"
	templateCacheTTL = 24 * time.Hour
	maxTemplates     = 10
)

// TemplateRequest is sent to the dast-templates edge function.
type TemplateRequest struct {
	TargetURL    string     `json:"targetURL"`
	Endpoints    []Endpoint `json:"endpoints"`
	TechHints    []string   `json:"techHints"`
	MaxTemplates int        `json:"maxTemplates"`
}

// TemplateResponse is returned by the dast-templates edge function.
type TemplateResponse struct {
	Templates []string `json:"templates"` // Nuclei YAML strings
	Rationale string   `json:"rationale"`
}

// GenerateTemplates calls the dast-templates edge function to generate custom
// Nuclei YAML templates for the crawled application. Results are cached locally
// for 24 hours based on the crawl content hash.
func GenerateTemplates(req TemplateRequest, accessToken string) (*TemplateResponse, error) {
	hash := crawlHash(req)

	// Check local cache first.
	if cached := loadTemplateCache(hash); cached != nil {
		return cached, nil
	}

	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}

	httpReq, err := http.NewRequest(http.MethodPost, dastTemplatesURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Authorization", "Bearer "+accessToken)
	httpReq.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("template generation request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var errBody struct {
			Error   string `json:"error"`
			Message string `json:"message"`
		}
		json.NewDecoder(resp.Body).Decode(&errBody) //nolint:errcheck
		if errBody.Error == "rate_limit_exceeded" {
			return nil, fmt.Errorf("rate_limit_exceeded")
		}
		return nil, fmt.Errorf("template generation failed (status %d)", resp.StatusCode)
	}

	var result TemplateResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	saveTemplateCache(hash, &result)
	return &result, nil
}

// WriteTemplatesToDir writes the YAML templates from a TemplateResponse into
// the given directory, creating it if necessary. Returns the directory path.
func WriteTemplatesToDir(resp *TemplateResponse, dir string) error {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	for i, yaml := range resp.Templates {
		path := filepath.Join(dir, fmt.Sprintf("template_%03d.yaml", i))
		if err := os.WriteFile(path, []byte(yaml), 0600); err != nil {
			return fmt.Errorf("writing template %d: %w", i, err)
		}
	}
	return nil
}

// crawlHash returns a stable hex hash of the crawl content for cache keying.
func crawlHash(req TemplateRequest) string {
	urls := make([]string, len(req.Endpoints))
	for i, e := range req.Endpoints {
		urls[i] = e.Method + ":" + e.URL
	}
	sort.Strings(urls)

	hints := append([]string{}, req.TechHints...)
	sort.Strings(hints)

	raw := req.TargetURL + "|" + fmt.Sprint(urls) + "|" + fmt.Sprint(hints)
	h := md5.Sum([]byte(raw))
	return fmt.Sprintf("%x", h)
}

func templateCacheDir(hash string) string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".trojan", "cache", "dast-templates", hash)
}

func loadTemplateCache(hash string) *TemplateResponse {
	dir := templateCacheDir(hash)
	metaPath := filepath.Join(dir, "meta.json")

	info, err := os.Stat(metaPath)
	if err != nil || time.Since(info.ModTime()) > templateCacheTTL {
		return nil
	}

	data, err := os.ReadFile(metaPath)
	if err != nil {
		return nil
	}

	var resp TemplateResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil
	}
	return &resp
}

func saveTemplateCache(hash string, resp *TemplateResponse) {
	dir := templateCacheDir(hash)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return
	}
	data, err := json.Marshal(resp)
	if err != nil {
		return
	}
	os.WriteFile(filepath.Join(dir, "meta.json"), data, 0600) //nolint:errcheck
}
