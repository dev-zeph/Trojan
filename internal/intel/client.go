package intel

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/dev-zeph/trojan/internal/config"
)

// intelURL is the hosted intel edge function. A var so tests can point the
// default client at an httptest server.
var intelURL = "https://dtmocojzvgsswjdsrmqr.supabase.co/functions/v1/intel"

// MaxPackagesPerRequest caps one request's inventory; larger inventories are
// sent in chunks and the advisories merged.
const MaxPackagesPerRequest = 5000

const defaultTimeout = 20 * time.Second

// ErrNotSignedIn means there is no saved Trojan session, or the server
// rejected it (401). The user should sign in in the Trojan app.
var ErrNotSignedIn = errors.New("not signed in to Trojan")

// ErrSubscriptionRequired is the sentinel behind SubscriptionRequiredError
// (402): intel is a paid feature and this account doesn't have it.
var ErrSubscriptionRequired = errors.New("subscription required")

// SubscriptionRequiredError carries the server's user-facing message.
// errors.Is(err, ErrSubscriptionRequired) matches it.
type SubscriptionRequiredError struct{ Message string }

func (e *SubscriptionRequiredError) Error() string {
	if e.Message != "" {
		return e.Message
	}
	return ErrSubscriptionRequired.Error()
}

func (e *SubscriptionRequiredError) Unwrap() error { return ErrSubscriptionRequired }

// Response is the intel edge function's 200 body.
type Response struct {
	Advisories  []Advisory `json:"advisories"`
	GeneratedAt string     `json:"generated_at"`
}

// Client calls the intel edge function.
type Client struct {
	// URL defaults to the production intel function.
	URL string
	// HTTPClient defaults to one with a 20s timeout.
	HTTPClient *http.Client
	// Token returns the user's access token. Defaults to the session saved by
	// `trojan login` / the desktop app (~/.trojan/config.json), the same
	// source every other hosted-function caller uses.
	Token func() (string, error)
}

// NewClient returns a client with production defaults.
func NewClient() *Client { return &Client{} }

// savedAccessToken reads the signed-in user's Supabase access token.
func savedAccessToken() (string, error) {
	cfg, err := config.LoadConfig()
	if err != nil || cfg.AccessToken == "" {
		return "", ErrNotSignedIn
	}
	return cfg.AccessToken, nil
}

type wirePackage struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
	Version   string `json:"version"`
}

// Fetch sends the inventory (deduplicated, chunked at MaxPackagesPerRequest)
// and returns every advisory the server knows for those packages. The body is
// base64-wrapped ({"encoded": ...}) like every other Go caller of the edge
// functions, so Cloudflare's WAF never sees raw payloads. Advisories from
// several chunks are merged (deduplicated by id+ecosystem+package);
// GeneratedAt is the first chunk's.
func (c *Client) Fetch(ctx context.Context, pkgs []Package) (*Response, error) {
	seen := map[string]bool{}
	var wire []wirePackage
	for _, p := range pkgs {
		w := wirePackage{Ecosystem: normEcosystem(p.Ecosystem), Name: p.Name, Version: p.Version}
		k := w.Ecosystem + "\x00" + w.Name + "\x00" + w.Version
		if seen[k] {
			continue
		}
		seen[k] = true
		wire = append(wire, w)
	}
	merged := &Response{Advisories: []Advisory{}}
	if len(wire) == 0 {
		return merged, nil
	}
	advSeen := map[string]bool{}
	for start := 0; start < len(wire); start += MaxPackagesPerRequest {
		end := min(start+MaxPackagesPerRequest, len(wire))
		resp, err := c.fetchChunk(ctx, wire[start:end])
		if err != nil {
			return nil, err
		}
		if merged.GeneratedAt == "" {
			merged.GeneratedAt = resp.GeneratedAt
		}
		for _, a := range resp.Advisories {
			k := a.ID + "\x00" + normEcosystem(a.Ecosystem) + "\x00" + normName(a.Ecosystem, a.Package)
			if advSeen[k] {
				continue
			}
			advSeen[k] = true
			merged.Advisories = append(merged.Advisories, a)
		}
	}
	return merged, nil
}

func (c *Client) fetchChunk(ctx context.Context, pkgs []wirePackage) (*Response, error) {
	tokenFn := c.Token
	if tokenFn == nil {
		tokenFn = savedAccessToken
	}
	token, err := tokenFn()
	if err != nil {
		return nil, err
	}
	if token == "" {
		return nil, ErrNotSignedIn
	}
	inner, err := json.Marshal(map[string]any{"packages": pkgs})
	if err != nil {
		return nil, err
	}
	body, err := json.Marshal(map[string]string{"encoded": base64.StdEncoding.EncodeToString(inner)})
	if err != nil {
		return nil, err
	}
	url := c.URL
	if url == "" {
		url = intelURL
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	hc := c.HTTPClient
	if hc == nil {
		hc = &http.Client{Timeout: defaultTimeout}
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("intel request failed: %w", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return nil, fmt.Errorf("reading intel response: %w", err)
	}

	switch resp.StatusCode {
	case http.StatusOK:
		var out Response
		if err := json.Unmarshal(data, &out); err != nil {
			return nil, fmt.Errorf("malformed intel response: %w", err)
		}
		if out.Advisories == nil {
			// A 200 without an advisories array is not a valid "no hits".
			var probe map[string]json.RawMessage
			if json.Unmarshal(data, &probe) != nil || probe["advisories"] == nil {
				return nil, errors.New("malformed intel response: missing advisories")
			}
			out.Advisories = []Advisory{}
		}
		return &out, nil
	case http.StatusUnauthorized:
		return nil, ErrNotSignedIn
	case http.StatusPaymentRequired:
		var e struct {
			Error   string `json:"error"`
			Message string `json:"message"`
		}
		json.Unmarshal(data, &e) //nolint:errcheck
		return nil, &SubscriptionRequiredError{Message: e.Message}
	}
	var e struct {
		Error   string `json:"error"`
		Message string `json:"message"`
	}
	json.Unmarshal(data, &e) //nolint:errcheck
	msg := e.Message
	if msg == "" {
		msg = e.Error
	}
	if msg == "" {
		msg = http.StatusText(resp.StatusCode)
	}
	return nil, &StatusError{Code: resp.StatusCode, Message: msg}
}

// StatusError is any non-200/401/402 reply from the intel function.
type StatusError struct {
	Code    int
	Message string
}

func (e *StatusError) Error() string {
	return fmt.Sprintf("intel request failed (status %d): %s", e.Code, e.Message)
}
