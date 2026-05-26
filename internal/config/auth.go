package config

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
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
	// IsPro is derived from the JWT claims on every load — not stored separately.
	// LicenseCheckedAt kept for backwards compat but no longer used.
	IsPro            bool      `json:"is_pro"`
	LicenseCheckedAt time.Time `json:"license_checked_at"`
}

// jwtClaims are the fields we care about inside the Supabase access token.
type jwtClaims struct {
	Email              string `json:"email"`
	SubscriptionStatus string `json:"subscription_status"`
	Exp                int64  `json:"exp"`
}

// parseJWTClaims decodes the payload section of a JWT without verifying
// the signature (verification is done server-side on every API call).
func parseJWTClaims(token string) (*jwtClaims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid JWT format")
	}
	// JWT uses base64url (no padding)
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("could not decode JWT payload: %w", err)
	}
	var claims jwtClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("could not parse JWT claims: %w", err)
	}
	return &claims, nil
}

// IsProFromToken reads subscription_status directly from the JWT claims.
// No network call needed — the claim is baked in by the Supabase auth hook.
func IsProFromToken(accessToken string) bool {
	claims, err := parseJWTClaims(accessToken)
	if err != nil {
		return false
	}
	return claims.SubscriptionStatus == "pro" || claims.SubscriptionStatus == "team"
}

// SubscriptionStatusFromToken returns the plan name from the JWT.
func SubscriptionStatusFromToken(accessToken string) string {
	claims, err := parseJWTClaims(accessToken)
	if err != nil {
		return "free"
	}
	if claims.SubscriptionStatus == "" {
		return "free"
	}
	return claims.SubscriptionStatus
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

// Logout removes the saved credentials from disk.
func Logout() error {
	return os.Remove(ConfigPath())
}

// IsLoggedIn returns true if the user has a valid token.
func IsLoggedIn() bool {
	cfg, err := LoadConfig()
	if err != nil {
		return false
	}
	return cfg.AccessToken != "" && time.Now().Before(cfg.ExpiresAt)
}

const supabaseAnonKey = "sb_publishable_U1qvJb7QebxgH5_0HCMYJQ_jKBybATQ"

// Login opens the Trojan login page in the browser and waits for the user
// to authenticate (email/password or GitHub). Both paths POST a token back
// to the local /token endpoint.
func Login() error {
	tokenCh := make(chan *TrojanConfig, 1)
	errCh   := make(chan error, 1)

	mux := http.NewServeMux()
	srv := &http.Server{Addr: fmt.Sprintf("127.0.0.1:%d", oauthCallbackPort), Handler: mux}

	callbackURL := fmt.Sprintf("http://127.0.0.1:%d/callback", oauthCallbackPort)
	githubURL := fmt.Sprintf(
		"%s/auth/v1/authorize?provider=github&redirect_to=%s",
		supabaseURL, callbackURL,
	)

	// GET / — login page with email form + GitHub button
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		page := strings.ReplaceAll(loginPageHTML, "{{GITHUB_URL}}", githubURL)
		page = strings.ReplaceAll(page, "{{SUPABASE_URL}}", supabaseURL)
		page = strings.ReplaceAll(page, "{{ANON_KEY}}", supabaseAnonKey)
		fmt.Fprint(w, page)
	})

	// GET /callback — GitHub OAuth lands here (token in URL fragment)
	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, callbackHTML)
	})

	// POST /token — receives access_token from both email and GitHub paths
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Access-Control-Allow-Origin", "*")
		var payload struct {
			AccessToken  string `json:"access_token"`
			RefreshToken string `json:"refresh_token"`
			ExpiresIn    int    `json:"expires_in"`
			Email        string `json:"email"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
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
		fmt.Fprint(w, `{"ok":true}`)
	})

	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
	}()

	loginURL := fmt.Sprintf("http://127.0.0.1:%d", oauthCallbackPort)
	fmt.Println("Opening browser for login...")
	fmt.Printf("If the browser doesn't open, visit:\n%s\n\n", loginURL)
	browser.OpenURL(loginURL)

	select {
	case cfg := <-tokenCh:
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(ctx)

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
// and updates the local config. Throttled to once per hour to avoid hammering
// the API on every scan while still picking up plan changes quickly.
func RefreshLicense() error {
	cfg, err := LoadConfig()
	if err != nil {
		return err
	}
	if cfg.AccessToken == "" {
		return nil
	}
	// Throttle: only re-fetch once per hour
	if time.Since(cfg.LicenseCheckedAt) < 1*time.Hour {
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

// ForceRefreshLicense re-fetches subscription status unconditionally, ignoring
// the throttle. Used by `trojan pro` after a user has just paid.
func ForceRefreshLicense() (*licenseResponse, error) {
	cfg, err := LoadConfig()
	if err != nil {
		return nil, err
	}
	if cfg.AccessToken == "" {
		return nil, fmt.Errorf("not logged in — run `trojan login` first")
	}
	info, err := fetchLicense(cfg.AccessToken)
	if err != nil {
		return nil, err
	}
	cfg.IsPro = info.IsPro
	cfg.LicenseCheckedAt = time.Now()
	return info, SaveConfig(cfg)
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

// loginPageHTML is the main login page with email/password and GitHub options.
// Placeholders: {{GITHUB_URL}}, {{SUPABASE_URL}}, {{ANON_KEY}}
const loginPageHTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Trojan — Sign in</title>
  <link rel="preconnect" href="https://fonts.googleapis.com" />
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
  <link href="https://fonts.googleapis.com/css2?family=Montserrat:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet" />
  <style>
    :root {
      --bg: #ffffff;
      --fg: #0a0a0a;
      --muted: #6b7280;
      --border: rgba(10,10,10,0.2);
      --input-bg: #ffffff;
      --card-bg: #ffffff;
      --hatch: rgba(10,10,10,0.07);
      --btn-bg: #0a0a0a;
      --btn-fg: #ffffff;
      --btn-hover: rgba(10,10,10,0.88);
      --error-bg: rgba(239,68,68,0.06);
      --error-border: rgba(239,68,68,0.3);
      --error-fg: #dc2626;
    }
    @media (prefers-color-scheme: dark) {
      :root {
        --bg: #0a0a0a;
        --fg: #fafafa;
        --muted: #9ca3af;
        --border: rgba(250,250,250,0.18);
        --input-bg: #0a0a0a;
        --card-bg: #0a0a0a;
        --hatch: rgba(250,250,250,0.06);
        --btn-bg: #fafafa;
        --btn-fg: #0a0a0a;
        --btn-hover: rgba(250,250,250,0.9);
        --error-bg: rgba(239,68,68,0.08);
        --error-border: rgba(239,68,68,0.35);
        --error-fg: #f87171;
      }
    }
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    html, body {
      min-height: 100%;
      font-family: 'Montserrat', system-ui, sans-serif;
      background: var(--bg);
      color: var(--fg);
      -webkit-font-smoothing: antialiased;
    }
    body {
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      min-height: 100vh;
      padding: 2rem;
      position: relative;
      overflow: hidden;
    }
    /* hatch pattern decorations */
    .hatch-l, .hatch-r {
      position: fixed;
      top: 0; bottom: 0;
      width: 30vw;
      pointer-events: none;
      background-image: repeating-linear-gradient(
        -45deg,
        transparent, transparent 14px,
        var(--hatch) 14px, var(--hatch) 15px
      );
    }
    .hatch-l { left: 0; -webkit-mask-image: linear-gradient(to right, transparent 0%, black 100%); mask-image: linear-gradient(to right, transparent 0%, black 100%); }
    .hatch-r { right: 0; -webkit-mask-image: linear-gradient(to left, transparent 0%, black 100%); mask-image: linear-gradient(to left, transparent 0%, black 100%); }
    .wrap {
      position: relative;
      z-index: 1;
      width: 100%;
      max-width: 420px;
    }
    /* logo wordmark */
    .logo-wrap {
      display: flex;
      justify-content: center;
      margin-bottom: 2.5rem;
    }
    .logo-text {
      font-family: 'JetBrains Mono', monospace;
      font-size: 1.5rem;
      font-weight: 500;
      letter-spacing: 0.18em;
      text-transform: uppercase;
      color: var(--fg);
      text-decoration: none;
    }
    /* card */
    .card {
      border: 1px solid var(--border);
      background: var(--card-bg);
      padding: 2.5rem;
    }
    .card-title {
      font-size: 1.4rem;
      font-weight: 700;
      letter-spacing: -0.02em;
      margin-bottom: 0.375rem;
    }
    .card-sub {
      font-size: 0.8rem;
      color: var(--muted);
      line-height: 1.6;
      margin-bottom: 2rem;
    }
    /* error */
    .error-box {
      display: none;
      padding: 0.75rem 1rem;
      border: 1px solid var(--error-border);
      background: var(--error-bg);
      color: var(--error-fg);
      font-size: 0.8rem;
      margin-bottom: 1.25rem;
    }
    .error-box.show { display: block; }
    /* form */
    .field { margin-bottom: 1rem; }
    label {
      display: block;
      font-size: 0.65rem;
      letter-spacing: 0.12em;
      text-transform: uppercase;
      color: var(--muted);
      margin-bottom: 0.5rem;
    }
    input[type="email"], input[type="password"] {
      width: 100%;
      border: 1px solid var(--border);
      background: var(--input-bg);
      color: var(--fg);
      padding: 0.625rem 0.875rem;
      font-family: 'Montserrat', system-ui, sans-serif;
      font-size: 0.875rem;
      outline: none;
      transition: border-color 0.15s;
    }
    input[type="email"]:focus, input[type="password"]:focus {
      border-color: var(--fg);
    }
    input::placeholder { color: var(--muted); opacity: 0.5; }
    /* primary button */
    .btn-primary {
      width: 100%;
      background: var(--btn-bg);
      color: var(--btn-fg);
      border: none;
      padding: 0.7rem 1rem;
      font-family: 'Montserrat', system-ui, sans-serif;
      font-size: 0.8rem;
      font-weight: 600;
      letter-spacing: 0.04em;
      cursor: pointer;
      transition: background 0.15s;
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 0.5rem;
      margin-top: 0.25rem;
    }
    .btn-primary:hover { background: var(--btn-hover); }
    .btn-primary:disabled { opacity: 0.5; cursor: not-allowed; }
    /* divider */
    .divider {
      display: flex;
      align-items: center;
      gap: 1rem;
      margin: 1.5rem 0;
    }
    .divider-line { flex: 1; height: 1px; background: var(--border); }
    .divider-text { font-size: 0.65rem; text-transform: uppercase; letter-spacing: 0.1em; color: var(--muted); }
    /* github button — drawn style */
    .btn-github {
      width: 100%;
      border: 1px solid var(--border);
      background: transparent;
      color: var(--fg);
      padding: 0.65rem 1rem;
      font-family: 'Montserrat', system-ui, sans-serif;
      font-size: 0.8rem;
      font-weight: 500;
      cursor: pointer;
      transition: background 0.15s;
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 0.625rem;
      text-decoration: none;
    }
    .btn-github:hover { background: rgba(128,128,128,0.07); }
    .btn-github svg { fill: currentColor; flex-shrink: 0; }
    /* toggle link */
    .toggle-row {
      margin-top: 1.75rem;
      text-align: center;
      font-size: 0.8rem;
      color: var(--muted);
    }
    .toggle-row button {
      background: none;
      border: none;
      color: var(--fg);
      font-size: 0.8rem;
      font-family: 'Montserrat', system-ui, sans-serif;
      cursor: pointer;
      text-decoration: underline;
      text-underline-offset: 3px;
    }
    /* footer note */
    .footer-note {
      margin-top: 1.5rem;
      text-align: center;
      font-size: 0.75rem;
      color: var(--muted);
    }
    .footer-note a { color: var(--fg); text-underline-offset: 3px; }
    /* spinner */
    .spin {
      width: 14px; height: 14px;
      border: 2px solid currentColor;
      border-top-color: transparent;
      border-radius: 50%;
      animation: spin 0.7s linear infinite;
    }
    @keyframes spin { to { transform: rotate(360deg); } }
  </style>
</head>
<body>
  <div class="hatch-l"></div>
  <div class="hatch-r"></div>

  <div class="wrap">
    <div class="logo-wrap">
      <span class="logo-text">Trojan</span>
    </div>

    <div class="card">
      <h1 class="card-title" id="title">Sign in to Trojan</h1>
      <p class="card-sub" id="subtitle">Sign in to activate Pro features and AI explanations in your terminal.</p>

      <div class="error-box" id="error"></div>

      <form id="form" autocomplete="on">
        <div class="field">
          <label for="email">Email</label>
          <input type="email" id="email" name="email" placeholder="you@example.com" required autocomplete="email" />
        </div>
        <div class="field">
          <label for="password">Password</label>
          <input type="password" id="password" name="password" placeholder="••••••••" required autocomplete="current-password" />
        </div>
        <button class="btn-primary" type="submit" id="submit-btn">
          <span id="submit-label">Sign in</span>
        </button>
      </form>

      <div class="divider">
        <div class="divider-line"></div>
        <span class="divider-text">or</span>
        <div class="divider-line"></div>
      </div>

      <a href="{{GITHUB_URL}}" class="btn-github">
        <svg width="16" height="16" viewBox="0 0 24 24"><path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0 0 24 12c0-6.63-5.37-12-12-12z"/></svg>
        Continue with GitHub
      </a>

      <div class="toggle-row">
        <span id="toggle-text">Don't have an account?</span>
        <button id="toggle-btn" type="button"> Sign up</button>
      </div>
    </div>

    <p class="footer-note">
      No account needed for free scanning. <a href="https://trojancli.com/docs">Install guide →</a>
    </p>
  </div>

  <script>
    const SUPABASE_URL = '{{SUPABASE_URL}}'
    const ANON_KEY = '{{ANON_KEY}}'
    let mode = 'signin'

    const form = document.getElementById('form')
    const submitBtn = document.getElementById('submit-btn')
    const submitLabel = document.getElementById('submit-label')
    const errorBox = document.getElementById('error')
    const titleEl = document.getElementById('title')
    const subtitleEl = document.getElementById('subtitle')
    const toggleBtn = document.getElementById('toggle-btn')
    const toggleText = document.getElementById('toggle-text')
    const pwInput = document.getElementById('password')

    toggleBtn.addEventListener('click', () => {
      mode = mode === 'signin' ? 'signup' : 'signin'
      if (mode === 'signup') {
        titleEl.textContent = 'Create your account'
        subtitleEl.textContent = 'Create an account to subscribe to Pro and unlock AI-powered explanations.'
        submitLabel.textContent = 'Create account'
        pwInput.autocomplete = 'new-password'
        toggleText.textContent = 'Already have an account?'
        toggleBtn.textContent = ' Sign in'
      } else {
        titleEl.textContent = 'Sign in to Trojan'
        subtitleEl.textContent = 'Sign in to activate Pro features and AI explanations in your terminal.'
        submitLabel.textContent = 'Sign in'
        pwInput.autocomplete = 'current-password'
        toggleText.textContent = "Don't have an account?"
        toggleBtn.textContent = ' Sign up'
      }
      errorBox.classList.remove('show')
    })

    form.addEventListener('submit', async (e) => {
      e.preventDefault()
      errorBox.classList.remove('show')
      submitBtn.disabled = true
      submitLabel.innerHTML = '<span class="spin"></span>'

      const email = document.getElementById('email').value
      const password = document.getElementById('password').value
      const endpoint = mode === 'signin'
        ? SUPABASE_URL + '/auth/v1/token?grant_type=password'
        : SUPABASE_URL + '/auth/v1/signup'

      try {
        const res = await fetch(endpoint, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'apikey': ANON_KEY },
          body: JSON.stringify({ email, password }),
        })
        const data = await res.json()

        if (!res.ok) {
          throw new Error(data.error_description || data.msg || data.error || 'Authentication failed.')
        }

        const token = data.access_token
        if (!token) {
          throw new Error('No session returned. Check your email for a confirmation link.')
        }

        await fetch('/token', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            access_token: data.access_token,
            refresh_token: data.refresh_token,
            expires_in: data.expires_in || 3600,
            email: data.user?.email || email,
          }),
        })

        document.querySelector('.card').innerHTML =
          '<p style="font-size:.65rem;letter-spacing:.12em;text-transform:uppercase;color:var(--muted);margin-bottom:.75rem">Signed in</p>' +
          '<h1 style="font-size:1.6rem;font-weight:700;letter-spacing:-.02em;margin-bottom:.5rem">You\'re in.</h1>' +
          '<p style="font-size:.85rem;color:var(--muted);line-height:1.6">Return to your terminal and run <code style="font-family:\'JetBrains Mono\',monospace;font-size:.8rem">trojan scan</code> to start scanning.</p>'
      } catch (err) {
        errorBox.textContent = err.message
        errorBox.classList.add('show')
        submitBtn.disabled = false
        submitLabel.textContent = mode === 'signin' ? 'Sign in' : 'Create account'
      }
    })
  </script>
</body>
</html>`

// callbackHTML is served after GitHub OAuth redirect — extracts the token from
// the URL fragment and POSTs it to the local /token endpoint.
const callbackHTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Trojan — Signing in</title>
  <link rel="preconnect" href="https://fonts.googleapis.com" />
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
  <link href="https://fonts.googleapis.com/css2?family=Montserrat:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet" />
  <style>
    :root {
      --bg: #ffffff; --fg: #0a0a0a; --muted: #6b7280; --border: rgba(10,10,10,0.2);
      --hatch: rgba(10,10,10,0.07);
    }
    @media (prefers-color-scheme: dark) {
      :root { --bg: #0a0a0a; --fg: #fafafa; --muted: #9ca3af; --border: rgba(250,250,250,0.18); --hatch: rgba(250,250,250,0.06); }
    }
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    html, body { min-height: 100%; font-family: 'Montserrat', system-ui, sans-serif; background: var(--bg); color: var(--fg); -webkit-font-smoothing: antialiased; }
    body { display: flex; align-items: center; justify-content: center; min-height: 100vh; padding: 2rem; position: relative; overflow: hidden; }
    .hatch-l, .hatch-r { position: fixed; top: 0; bottom: 0; width: 30vw; pointer-events: none; background-image: repeating-linear-gradient(-45deg, transparent, transparent 14px, var(--hatch) 14px, var(--hatch) 15px); }
    .hatch-l { left: 0; -webkit-mask-image: linear-gradient(to right, transparent 0%, black 100%); mask-image: linear-gradient(to right, transparent 0%, black 100%); }
    .hatch-r { right: 0; -webkit-mask-image: linear-gradient(to left, transparent 0%, black 100%); mask-image: linear-gradient(to left, transparent 0%, black 100%); }
    .wrap { position: relative; z-index: 1; width: 100%; max-width: 420px; }
    .logo-wrap { display: flex; justify-content: center; margin-bottom: 2.5rem; }
    .logo-text { font-family: 'JetBrains Mono', monospace; font-size: 1.5rem; font-weight: 500; letter-spacing: .18em; text-transform: uppercase; color: var(--fg); }
    .card { border: 1px solid var(--border); padding: 2.5rem; text-align: center; }
    .label { font-size: .65rem; letter-spacing: .12em; text-transform: uppercase; color: var(--muted); margin-bottom: .75rem; display: flex; align-items: center; justify-content: center; gap: .4rem; }
    .dot { width: 6px; height: 6px; border-radius: 50%; background: #10b981; display: inline-block; animation: pulse 1.4s ease-in-out infinite; }
    @keyframes pulse { 0%,100%{opacity:1}50%{opacity:.25} }
    .title { font-size: 1.4rem; font-weight: 700; letter-spacing: -.02em; margin-bottom: .5rem; }
    .sub { font-size: .85rem; color: var(--muted); line-height: 1.6; }
    code { font-family: 'JetBrains Mono', monospace; font-size: .8rem; }
  </style>
</head>
<body>
  <div class="hatch-l"></div>
  <div class="hatch-r"></div>
  <div class="wrap">
    <div class="logo-wrap"><span class="logo-text">Trojan</span></div>
    <div class="card" id="card">
      <p class="label"><span class="dot"></span>Authenticating</p>
      <h1 class="title">Completing sign-in</h1>
      <p class="sub">Exchanging credentials with GitHub. This only takes a moment.</p>
    </div>
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
        '<p class="label">Signed in</p>' +
        '<h1 class="title">You\'re in.</h1>' +
        '<p class="sub">Return to your terminal and run <code>trojan scan</code> to start scanning.</p>'
    }).catch(() => {
      document.getElementById('card').innerHTML =
        '<p class="label">Error</p>' +
        '<h1 class="title">Something went wrong.</h1>' +
        '<p class="sub">Close this tab and try <code>trojan login</code> again.</p>'
    })
  </script>
</body>
</html>`
