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

### Production (packaged `.app`)

1. User clicks **Sign in** in the app shell.
2. `open_auth` opens `https://trojancli.com/login?redirect=trojan://auth/callback` in the system browser.
3. After login the website redirects to `trojan://auth/callback?token=...&name=...&email=...`.
4. macOS routes the deep link to the `.app`; Tauri emits a `deep-link-received` event.
5. The React frontend calls `sync_auth` to write `~/.trojan/config.json`.

### Development (`npm run tauri dev`)

macOS does **not** register the `trojan://` scheme for the dev server — only the installed `.app` receives deep links. A local HTTP callback server is used instead:

1. User clicks **Sign in**.
2. `start_auth_callback` (Rust) spins up a one-shot TCP listener on a random port → returns that port.
3. `open_auth` opens `https://trojancli.com/login?redirect=http://127.0.0.1:<port>/callback`.
4. The website detects `http://127.0.0.1` as a desktop redirect and activates the desktop auth flow.
5. After login the website routes to `/auth/desktop-callback?redirect=http://127.0.0.1:<port>/callback`, exchanges the OAuth code for a session, then redirects to `http://127.0.0.1:<port>/callback?token=...`.
6. The TCP server catches the request, emits an `auth-callback` Tauri event, sends a self-closing success page to the browser.
7. The React frontend handles `auth-callback`, calls `sync_auth`, and marks the user as logged in.

> **PRODUCTION CLEANUP REQUIRED** — see section below.

---

## ⚠ Dev-Only Changes — Remove Before Shipping

Two temporary changes were made to support the local HTTP callback approach during development. **Both must be reverted before production deployment:**

### 1. `trojan-web/frontend/app/login/login-card.tsx` — `isDesktop` check

**Current (dev):**
```tsx
const isDesktop = (
  desktopRedirect?.startsWith("trojan://") ||
  desktopRedirect?.startsWith("http://127.0.0.1")   // DEV ONLY
) === true;
```

**Revert to (production):**
```tsx
const isDesktop = desktopRedirect?.startsWith("trojan://") === true;
```

**Why:** `http://127.0.0.1` redirects are only valid when the dev server is running locally. Accepting them in production would widen the open-redirect surface to any localhost address.

---

### 2. `trojan-web/frontend/app/auth/desktop-callback/route.ts` — security guard

**Current (dev):**
```ts
if (!redirect.startsWith('trojan://') && !redirect.startsWith('http://127.0.0.1')) {
  // DEV ONLY — http://127.0.0.1 branch
```

**Revert to (production):**
```ts
if (!redirect.startsWith('trojan://')) {
```

**Why:** The `http://127.0.0.1` allowance is intentionally locked to loopback, but it still accepts an arbitrary port number. In production the deep-link scheme (`trojan://`) is sufficient and carries no open-redirect risk.

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
