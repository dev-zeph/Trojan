package ai

import (
	"bytes"
	"crypto/md5"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/dev-zeph/trojan/internal/normalizer"
)

// synthesizeURL is a var (not const) so tests can point it at an
// httptest.NewServer instead of the real edge function.
var synthesizeURL = "https://dtmocojzvgsswjdsrmqr.supabase.co/functions/v1/synthesize"

// OverrideSynthesizeURL is a test-only hook: it points SynthesizeFinding at a
// stub server (e.g. httptest.NewServer) and returns a func that restores the
// real edge function URL. Exported because callers in other packages (like
// cmd/trojan's concurrent-synthesis tests) need to stub the network too.
func OverrideSynthesizeURL(url string) (restore func()) {
	orig := synthesizeURL
	synthesizeURL = url
	return func() { synthesizeURL = orig }
}

const (
	licenseURL = "https://dtmocojzvgsswjdsrmqr.supabase.co/functions/v1/license"
)

// ErrInsufficientTokens is the sentinel behind every InsufficientTokensError.
// Callers that don't need the balance can just check errors.Is(err,
// ErrInsufficientTokens) instead of type-asserting.
var ErrInsufficientTokens = errors.New("insufficient trojan tokens")

// InsufficientTokensError means the edge function returned 402: the request
// itself was fine, the user's Trojan Token balance just can't cover it. This
// is not a failure in the ordinary sense -- it's the single most important
// message this feature can return, so it needs to be distinguishable from a
// generic synthesis error rather than collapsed into one. Balance and Message
// are parsed from the JSON body the edge function sends alongside the 402.
type InsufficientTokensError struct {
	Balance int
	Message string
}

func (e *InsufficientTokensError) Error() string {
	if e.Message != "" {
		return e.Message
	}
	return fmt.Sprintf("insufficient trojan tokens, balance: %d", e.Balance)
}

// Unwrap lets errors.Is(err, ErrInsufficientTokens) succeed alongside
// errors.As(err, &insufficientTokensErr) for callers that want the balance.
func (e *InsufficientTokensError) Unwrap() error {
	return ErrInsufficientTokens
}

// Synthesis holds the AI-generated explanation and fix steps for a finding.
type Synthesis struct {
	Simply          string   `json:"simply"`
	Actions         []string `json:"actions"`
	Confidence      int      `json:"confidence,omitempty"`
	IsFalsePositive bool     `json:"isFalsePositive,omitempty"`
	FixDiff         string   `json:"fixDiff,omitempty"`
}

// LicenseInfo holds the user's subscription status fetched from the backend.
type LicenseInfo struct {
	IsPro              bool   `json:"isPro"`
	SubscriptionStatus string `json:"subscriptionStatus"`
	Email              string `json:"email"`
	// TokenBalance is the user's remaining Trojan Tokens -- the BILLING unit
	// they purchase and spend, not LLM tokens. Rides along on the license call
	// because both the CLI and the desktop already poll it.
	TokenBalance int `json:"tokenBalance"`
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
// familiarity controls the tone: 0 = non-technical, 1 = junior dev, 2 = experienced.
// aboutYou is free-form context from the user's profile.
func SynthesizeFinding(finding normalizer.Finding, accessToken string, familiarity int, aboutYou string) (*Synthesis, error) {
	// Check local cache first
	if cached := loadFromCache(finding, familiarity); cached != nil {
		return cached, nil
	}

	payload := map[string]any{
		"ruleId":          finding.RuleID,
		"scanner":         finding.Scanner,
		"category":        finding.Category,
		"severity":        string(finding.Severity),
		"title":           finding.Title,
		"rawMessage":      finding.RawMessage,
		"language":        finding.Language,
		"filePath":        finding.FilePath,
		"codeSnippet":     finding.CodeSnippet,
		"surroundingCode": finding.SurroundingCode,
		"projectType":     finding.ProjectType,
		"framework":       finding.Framework,
		"familiarity":     familiarity,
		"aboutYou":        aboutYou,
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

	if resp.StatusCode == http.StatusPaymentRequired {
		// The edge function's 402 body is {"error":"insufficient_tokens",
		// "message":..., "balance":N}. Best-effort decode: even if the body is
		// missing or malformed, still return a distinguishable error rather
		// than falling through to the generic one below.
		var body struct {
			Message string `json:"message"`
			Balance int    `json:"balance"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&body)
		return nil, &InsufficientTokensError{Balance: body.Balance, Message: body.Message}
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("synthesis failed (status %d)", resp.StatusCode)
	}

	var synthesis Synthesis
	if err := json.NewDecoder(resp.Body).Decode(&synthesis); err != nil {
		return nil, err
	}

	saveToCache(finding, familiarity, &synthesis)
	return &synthesis, nil
}

// cachePath returns the local cache file path for a finding.
// The key includes a 4-byte hash of the code snippet + file path + familiarity
// so that the same rule at different tone levels gets its own cached explanation.
// familiarity is passed in rather than read off a package-level var: synthesis
// runs many findings concurrently (see cmd/trojan's synthesizeConcurrently),
// and a shared mutable global here would race across those goroutines.
func cachePath(f normalizer.Finding, familiarity int) string {
	home, _ := os.UserHomeDir()
	h := md5.Sum([]byte(f.CodeSnippet + f.FilePath + fmt.Sprintf("%d", familiarity)))
	key := fmt.Sprintf("%s-%s-%x.json", sanitize(f.RuleID), sanitize(f.Scanner), h[:4])
	return filepath.Join(home, ".trojan", "cache", key)
}

const cacheTTL = 30 * 24 * time.Hour // AI explanations refresh every 30 days

func loadFromCache(f normalizer.Finding, familiarity int) *Synthesis {
	p := cachePath(f, familiarity)

	info, err := os.Stat(p)
	if err != nil || time.Since(info.ModTime()) > cacheTTL {
		return nil
	}

	data, err := os.ReadFile(p)
	if err != nil {
		return nil
	}
	var s Synthesis
	if err := json.Unmarshal(data, &s); err != nil {
		return nil
	}
	return &s
}

func saveToCache(f normalizer.Finding, familiarity int, s *Synthesis) {
	path := cachePath(f, familiarity)
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
