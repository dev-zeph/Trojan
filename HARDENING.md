# Trojan — Hardening Tracker

Customer personas: **Non-technical founder** (wants proof, clean reports, plain language) and **Experienced developer** (wants technical depth, actionable fixes, CI integration).

---

## 🔴 Ship Blockers

### SB-1 · Threat Lab print = blank page
- **What:** Clicking print in the Threat Lab view produces a blank PDF. The browser renders the full app shell, not the certificate.
- **Impact:** Non-tech founder's primary investor/customer artifact is broken.
- **Fix:** Dedicated `PrintCertificate` component with `@media print` CSS that hides `.app-layout` and shows only the certificate. QR code links to `trojancli.com`.
- **Status:** [x] DONE

### SB-2 · No scan cancellation — UI spins forever
- **What:** If the Go sidecar hangs, crashes, or the user wants to abort, there is no way to cancel. The scanning toast and button stay in loading state permanently.
- **Impact:** Both personas. Leaves the app in an unrecoverable state without a restart.
- **Fix:** Expose a `cancel_scan` Tauri command that calls `kill_old_scans` + emits a `scan-cancelled` event. Show a "Cancel" button during active scans.
- **Status:** [x] DONE

### SB-3 · Supabase JWT expires mid-session silently
- **What:** Access tokens expire after 1 hour. Threat Lab calls and AI translations silently fail with 401 errors because the token isn't refreshed before use.
- **Impact:** Both personas. The user has no idea why "Run Threat Lab" stopped working.
- **Fix:** Before every Supabase call, call `supabase.auth.getSession()` (which auto-refreshes) and update the stored token. Show a clear "Session expired — sign in again" banner if refresh fails.
- **Status:** [x] DONE

---

## 🟡 Polish Blockers

### PB-1 · Error messages are developer strings
- **What:** Internal errors like `"spawn failed: {e}"`, `"sidecar not found"`, `"Scan failed: process exited (code 1)"` surface directly to the user.
- **Impact:** Non-tech founder has no idea what these mean or what to do.
- **Fix:** Map known internal error patterns to human messages. E.g., "sidecar not found" → "Could not start the scanner. Try reinstalling Trojan." 
- **Status:** [x] DONE

### PB-2 · No familiarity context — AI explains the same to everyone
- **What:** Threat Lab and AI translations give the same technical depth to a CTO and a Rails developer with no security background.
- **Impact:** Non-tech founder gets jargon; experienced developer gets hand-holding they don't need.
- **Fix:** User Profile tab with a familiarity slider (Non-technical founder ↔ Experienced developer), project description, and name. Stored in `UserProfile`. Wired into Threat Lab system prompt and `synthesize` edge function.
- **Status:** [x] DONE

### PB-3 · Stale history entries cause silent failures
- **What:** History entries with `cachePath` pointing to deleted files silently fail when the user tries to reopen them. No feedback, nothing happens.
- **Impact:** Both personas. Old scans appear clickable but do nothing.
- **Fix:** On load, validate cache paths exist before showing "Open" buttons. Show a "Cache removed" badge on stale entries.
- **Status:** [x] DONE

### PB-4 · Terminal height not saved across restarts
- **What:** The terminal panel always resets to 220px on app restart.
- **Impact:** Developer. Minor but annoying — they resize it once and have to again.
- **Fix:** Persist `terminalHeight` and `terminalOpen` to `tauri-plugin-store`.
- **Status:** [x] DONE

### PB-5 · Empty state is unclear for first-time users
- **What:** Overview dashboard shows metrics and rings with no data and no clear "start here" prompt. A non-tech founder opening the app for the first time doesn't know what to do.
- **Impact:** Non-tech founder especially. Developer will figure it out.
- **Fix:** When no scan has run yet, show a focused empty state: app icon, one sentence of what Trojan does, and a single "Scan a project" CTA button.
- **Status:** [x] DONE

### PB-6 · Scan history has no delete
- **What:** History entries accumulate with no way to remove individual items or clear all.
- **Impact:** Both, minor.
- **Fix:** Swipe-to-delete or a `×` button on each history row. Clear all in settings.
- **Status:** [x] DONE

---

## Implementation Order

1. **SB-1** — PDF certificate (print fix + proper layout)
2. **PB-2** — User Profile tab + familiarity levels → wire into Threat Lab
3. **SB-2** — Scan cancellation
4. **SB-3** — JWT auto-refresh
5. **PB-1** — Human-readable error messages
6. **PB-3** — Stale history validation
7. **PB-4** — Persist terminal state
8. **PB-5** — First-run empty state
9. **PB-6** — History delete
