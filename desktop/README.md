# Trojan Desktop

A Tauri v2 wrapper around the Trojan security CLI, providing a native macOS/Windows/Linux desktop experience with an embedded scan report viewer and Supabase-backed authentication.

---

## Stack

| Layer | Tech |
|---|---|
| Shell | Tauri v2 (Rust) |
| Frontend | React + TypeScript + Vite |
| Auth | Supabase (email/password + GitHub OAuth) |
| Persistence | `tauri-plugin-store` (`trojan-store.json`) |
| Sidecar | Go binary (`trojan`) bundled inside `.app` |
| Deep link | `trojan://` scheme (macOS: Info.plist, Windows/Linux: runtime) |

---

## Architecture

```
desktop/
├── src/               React frontend
│   ├── App.tsx        Main shell — sidebar, nav, report iframe
│   └── App.css        Layout styles
└── src-tauri/
    ├── src/lib.rs     Rust commands (scan, auth, store)
    └── capabilities/  Tauri permission allowlists
```

The Go sidecar is started by Tauri via `tauri-plugin-shell`. When ready, it emits `READY <url>` on stdout and Trojan Desktop embeds the report URL in an always-mounted iframe so switching tabs doesn't reload the report.

Auth tokens are written to `~/.trojan/config.json` (via the `sync_auth` Rust command) so the Go sidecar's embedded React UI and Threat Lab feature gates see the same session without a second login.

---

## Auth Flow

### Auth flow (dev and production)

The TCP callback server is the production auth approach — it works identically in `tauri dev` and packaged `.app` builds. No deep-link scheme registration is required.

1. User clicks **Sign in**.
2. `start_auth_callback` (Rust) spins up a one-shot TCP listener on a random loopback port → returns that port.
3. `open_auth` opens `https://trojancli.com/login?redirect=http://127.0.0.1:<port>/callback` in the system browser.
4. The website recognises `http://127.0.0.1` as a desktop redirect and activates the desktop auth flow.
5. After login the website routes to `/auth/desktop-callback?redirect=http://127.0.0.1:<port>/callback`, exchanges the OAuth code for a session, then redirects to `http://127.0.0.1:<port>/callback?token=...`.
6. The TCP server catches the request, emits an `auth-callback` Tauri event, and sends a self-closing success page to the browser.
7. The React frontend handles `auth-callback`, calls `sync_auth`, and marks the user as logged in.

The `trojan://` deep-link scheme is wired as a fallback (macOS Info.plist) but is not the primary path. Both `login-card.tsx` and `desktop-callback/route.ts` intentionally accept `http://127.0.0.1` — this is correct production behaviour, not a dev-only workaround.

---

## Running Locally

```bash
# Install dependencies
npm install

# Start dev server (Vite + Tauri)
npm run tauri dev

# Build a production .app
npm run tauri build
```

When testing auth in dev mode, make sure the `trojan-web` frontend is running locally (or pointing to the deployed site) so the `http://127.0.0.1` redirect is accepted.

---

## Scan History

Recent scans are stored in `tauri-plugin-store` under the key `recentProjects`. Each entry contains:

```ts
{ path: string; url: string; cachePath: string; ts: number }
```

The cache path is the file written by the Go sidecar (`CACHE_PATH <path>` on stdout). `serve_scan` re-serves a cached result without re-running scanners.

---

## Config Written by Desktop

`sync_auth` writes `~/.trojan/config.json` in the exact shape expected by the Go server:

```json
{
  "access_token":       "<JWT>",
  "refresh_token":      "",
  "user_email":         "user@example.com",
  "expires_at":         "2025-12-31T00:00:00Z",
  "is_pro":             true,
  "license_checked_at": "0001-01-01T00:00:00Z"
}
```

This file is read on every `/api/auth/status` call by the embedded Go HTTP server, so Pro feature gates in the report iframe and Threat Lab work without a second login.
