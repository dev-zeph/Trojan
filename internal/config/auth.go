package config

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/pkg/browser"
)

const (
	supabaseURL      = "https://dtmocojzvgsswjdsrmqr.supabase.co"
	oauthCallbackPort = 7879
)

// TrojanConfig holds the user's local auth state.
type TrojanConfig struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	UserEmail    string    `json:"user_email"`
	ExpiresAt    time.Time `json:"expires_at"`
	IsPro        bool      `json:"is_pro"`
	LicenseCheckedAt time.Time `json:"license_checked_at"`
}

// ConfigPath returns the path to ~/.trojan/config.json
func ConfigPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".trojan", "config.json")
}

// LoadConfig reads the local config file.
func LoadConfig() (*TrojanConfig, error) {
	data, err := os.ReadFile(ConfigPath())
	if err != nil {
		return nil, err
	}
	var cfg TrojanConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// SaveConfig writes the config to disk.
func SaveConfig(cfg *TrojanConfig) error {
	path := ConfigPath()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

// IsLoggedIn returns true if the user has a valid token.
func IsLoggedIn() bool {
	cfg, err := LoadConfig()
	if err != nil {
		return false
	}
	return cfg.AccessToken != "" && time.Now().Before(cfg.ExpiresAt)
}

// Login opens the browser to GitHub OAuth via Supabase and waits for the callback.
func Login() error {
	// Start a local server to catch the OAuth callback
	tokenCh := make(chan *TrojanConfig, 1)
	errCh := make(chan error, 1)

	srv := &http.Server{Addr: fmt.Sprintf("127.0.0.1:%d", oauthCallbackPort)}

	http.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		// Supabase redirects with access_token in the URL fragment.
		// We serve a small HTML page that extracts it and POSTs it back.
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, callbackHTML)
	})

	http.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			return
		}
		var payload struct {
			AccessToken  string `json:"access_token"`
			RefreshToken string `json:"refresh_token"`
			ExpiresIn    int    `json:"expires_in"`
			Email        string `json:"email"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			errCh <- err
			return
		}

		cfg := &TrojanConfig{
			AccessToken:  payload.AccessToken,
			RefreshToken: payload.RefreshToken,
			UserEmail:    payload.Email,
			ExpiresAt:    time.Now().Add(time.Duration(payload.ExpiresIn) * time.Second),
		}

		tokenCh <- cfg
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"ok":true}`)
	})

	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
	}()

	// Build the GitHub OAuth URL via Supabase
	callbackURL := fmt.Sprintf("http://127.0.0.1:%d/callback", oauthCallbackPort)
	authURL := fmt.Sprintf(
		"%s/auth/v1/authorize?provider=github&redirect_to=%s",
		supabaseURL,
		callbackURL,
	)

	fmt.Println("Opening browser for GitHub login...")
	fmt.Printf("If the browser doesn't open, visit:\n%s\n\n", authURL)

	browser.OpenURL(authURL)

	// Wait for token or timeout
	select {
	case cfg := <-tokenCh:
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(ctx)

		// Fetch and cache subscription status
		if info, err := fetchLicense(cfg.AccessToken); err == nil {
			cfg.IsPro = info.IsPro
			cfg.LicenseCheckedAt = time.Now()
			if info.Email != "" {
				cfg.UserEmail = info.Email
			}
		}

		if err := SaveConfig(cfg); err != nil {
			return fmt.Errorf("could not save config: %w", err)
		}
		return nil

	case err := <-errCh:
		return err

	case <-time.After(5 * time.Minute):
		return fmt.Errorf("login timed out")
	}
}

// RefreshLicense re-fetches the user's subscription status from the backend
// and updates the local config. Called weekly to keep Pro status current.
func RefreshLicense() error {
	cfg, err := LoadConfig()
	if err != nil {
		return err
	}
	if cfg.AccessToken == "" {
		return nil
	}
	// Only refresh once per week
	if time.Since(cfg.LicenseCheckedAt) < 7*24*time.Hour {
		return nil
	}
	info, err := fetchLicense(cfg.AccessToken)
	if err != nil {
		return err
	}
	cfg.IsPro = info.IsPro
	cfg.LicenseCheckedAt = time.Now()
	return SaveConfig(cfg)
}

type licenseResponse struct {
	IsPro              bool   `json:"isPro"`
	SubscriptionStatus string `json:"subscriptionStatus"`
	Email              string `json:"email"`
}

func fetchLicense(accessToken string) (*licenseResponse, error) {
	req, err := http.NewRequest(http.MethodGet,
		"https://dtmocojzvgsswjdsrmqr.supabase.co/functions/v1/license", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("license check failed (status %d)", resp.StatusCode)
	}

	var info licenseResponse
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return nil, err
	}
	return &info, nil
}

// callbackHTML is served after OAuth redirect — extracts the token from the URL fragment
// and POSTs it to our local server.
const callbackHTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Trojan — Logging in</title>
  <link rel="preconnect" href="https://fonts.googleapis.com" />
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&display=swap" rel="stylesheet" />
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    html, body {
      height: 100%;
      font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
      background: #ffffff;
      color: #0a0a0a;
      -webkit-font-smoothing: antialiased;
    }
    body {
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      min-height: 100vh;
      padding: 2rem;
    }
    .logo {
      width: 64px;
      height: auto;
      margin-bottom: 2.5rem;
    }
    .card {
      max-width: 400px;
      width: 100%;
      text-align: center;
    }
    .status {
      font-size: 0.75rem;
      letter-spacing: 0.12em;
      text-transform: uppercase;
      color: #6b7280;
      margin-bottom: 1rem;
    }
    .title {
      font-size: 1.25rem;
      font-weight: 600;
      letter-spacing: -0.02em;
      color: #0a0a0a;
      margin-bottom: 0.5rem;
    }
    .subtitle {
      font-size: 0.875rem;
      color: #6b7280;
      line-height: 1.5;
    }
    .divider {
      width: 32px;
      height: 1px;
      background: #e5e7eb;
      margin: 2rem auto;
    }
    .hint {
      font-size: 0.75rem;
      color: #9ca3af;
    }
    .dot {
      display: inline-block;
      width: 6px;
      height: 6px;
      border-radius: 50%;
      background: #10b981;
      margin-right: 0.4rem;
      vertical-align: middle;
      animation: pulse 1.5s ease-in-out infinite;
    }
    @keyframes pulse {
      0%, 100% { opacity: 1; }
      50% { opacity: 0.3; }
    }
    .success .dot { animation: none; }
    .success .dot { background: #10b981; }
  </style>
</head>
<body>
  <div class="card" id="card">
    <img src="/logo.png" alt="Trojan" class="logo" />
    <p class="status"><span class="dot"></span>Authenticating</p>
    <h1 class="title">Completing sign-in</h1>
    <p class="subtitle">Exchanging credentials with GitHub. This only takes a moment.</p>
    <div class="divider"></div>
    <p class="hint">You can close this tab once complete.</p>
  </div>

  <script>
    const hash = window.location.hash.substring(1)
    const params = new URLSearchParams(hash)
    const payload = {
      access_token: params.get('access_token'),
      refresh_token: params.get('refresh_token'),
      expires_in: parseInt(params.get('expires_in') || '3600'),
      email: params.get('email') || '',
    }
    fetch('/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    }).then(() => {
      document.getElementById('card').innerHTML =
        '<img src="/logo.png" alt="Trojan" class="logo" />' +
        '<p class="status success"><span class="dot"></span>Signed in</p>' +
        '<h1 class="title">You\'re in.</h1>' +
        '<p class="subtitle">Return to the terminal and run <code style="font-family:monospace;background:#f3f4f6;padding:0.1em 0.4em;border-radius:3px">trojan scan</code> to start scanning.</p>'
    }).catch(() => {
      document.getElementById('card').innerHTML =
        '<img src="/logo.png" alt="Trojan" class="logo" />' +
        '<p class="status">Error</p>' +
        '<h1 class="title">Something went wrong.</h1>' +
        '<p class="subtitle">Close this tab and try <code style="font-family:monospace;background:#f3f4f6;padding:0.1em 0.4em;border-radius:3px">trojan login</code> again.</p>'
    })
  </script>
</body>
</html>`
