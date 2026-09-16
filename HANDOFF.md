# Trojan Errors (crash analytics) — MVP handoff

Branch: `feat/crash-analytics-mvp` (worktree `Trojan-crash-analytics-mvp`).
Local commits only, nothing pushed.

Everything below runs on localhost and needs no cloud account, no secret, and
no Docker.

---

## TL;DR — run the demo

```bash
cd /Users/zephaniahchizulu/Desktop/Trojan-crash-analytics-mvp

# 1. One time only (~2 min). Installs the storage backend and provisions it.
./crash-analytics/setup.sh

# 2. Every time. Brings up all three services and health-checks each one.
./crash-analytics/start.sh

# 3. The desktop app (separate terminal). First run compiles Rust, ~2 min.
cd desktop && npm install && npm run tauri dev
```

Then:

1. Open <http://localhost:3003> — the sample "Checkout Service", standing in for
   a customer's deployed app. Click any red button to make it throw.
2. In the Trojan desktop app, click **Errors** in the left nav (under MONITORING).
3. The error appears within about five seconds.

Stop everything with `./crash-analytics/stop.sh`.

### Ports

| Port | Service | Notes |
|------|---------|-------|
| 8000 | Bugsink | storage backend, internal, customers never see it |
| 3002 | Trojan Errors shim | ingestion + read API |
| 3003 | Sample checkout service | the "customer app" being demoed |
| 1420 | Desktop app dev server | started by `npm run tauri dev` |

---

## What this is

A customer drops the standard `@sentry/node` SDK into their running app, pointed
at a Trojan DSN. When the app throws, Trojan captures the event, groups it with
past occurrences, and shows it in Trojan's own Errors tab.

```
customer's running app
  │  real @sentry/node SDK, Trojan DSN
  ▼
Trojan Errors shim        backend/src/errors/   :3002   <- our code
  │  auth, PII scrub, pen-test tagging, forward
  ▼
Bugsink                   crash-analytics/      :8000   <- OSS, invisible to customers
  │  fingerprint, group, store
  ▼
Trojan Errors shim        read API, normalized into Trojan shapes
  ▼
Trojan desktop app        Errors tab
```

---

## The one decision that changed: Docker

The locked research doc assumed self-hosting GlitchTip or Bugsink via
`docker-compose`. **Docker is not installed on this machine**, and the fallback
in the brief was to hand-roll the 5-stage pipeline instead.

Neither was necessary. **Bugsink runs fine as a plain Django app with no Docker
at all**: `uv venv` + `pip install bugsink`, migrate to SQLite, and run it with
`SNAPPEA.TASK_ALWAYS_EAGER` so no separate worker process is needed. Cold setup
is about two minutes, and `crash-analytics/setup.sh` does all of it
idempotently.

This matters because it means **we stayed on the locked "adopt an existing OSS
crash logger, don't build one" decision (§2)**. Grouping, fingerprinting,
retention and the Sentry wire protocol are all Bugsink's, not ours. No custom
capture protocol and no custom SDK was written.

Trojan's own code is only what §3 said it should be: a thin shim plus the
dashboard surface.

### Why there is still a shim

Customer SDKs do not point at Bugsink directly. They point at the shim, which:

1. Authenticates a **Trojan** project key, so customers never touch a Bugsink
   account.
2. **Scrubs PII** before anything is stored.
3. **Tags pen-test traffic** (§3a).
4. Normalizes reads into Trojan shapes, so the desktop never sees a Bugsink
   field name.

Point 4 is what keeps the backend swappable. Every Bugsink-specific name is
confined to `backend/src/errors/backends/bugsink.ts` behind an `ErrorsBackend`
interface. Moving to GlitchTip means adding `backends/glitchtip.ts` and changing
one line, exactly as §2 promised.

---

## What was built

| Path | What |
|------|------|
| `crash-analytics/setup.sh` | One-shot Bugsink install, migrate, provision. Idempotent. |
| `crash-analytics/bugsink/provision.py` | Creates the project + service token, emits `runtime.json`. |
| `crash-analytics/start.sh` / `stop.sh` | Bring the stack up/down, health-checked, adopts already-running services. |
| `crash-analytics/CONTRACT.md` | The API contract the pieces were built against. |
| `crash-analytics/SETUP.md` | Customer-facing copy-paste setup guide (Node + Python). |
| `crash-analytics/sample-app/` | The breakable "Checkout Service" demo, using the real `@sentry/node`. |
| `backend/src/errors/` | The shim: ingestion, scrubbing, pen-test tagging, read API. |
| `desktop/src/App.tsx`, `App.css` | The Errors tab. |
| `internal/errmon/`, `cmd/trojan/main.go` | Go side of pen-test muting. |

### Runs with no install and no secrets

The shim is plain `node backend/src/errors/server.ts`. Node 25 strips
TypeScript natively, so there is no build step, no `tsx`, and no
`backend/node_modules`. It deliberately does **not** import `backend/src/supabase.ts`,
which throws at module load without `SUPABASE_URL` / `SUPABASE_SERVICE_ROLE_KEY`
— there is no `.env` in this repo, so the existing backend on :3001 cannot boot
here at all. That is why Errors is a separate entrypoint rather than another
route on `backend/src/index.ts`.

---

## Verified end to end

Done by hand, in the real desktop app, not just against the API:

- A real `@sentry/node` event from the sample app on :3003 reaches the Errors
  tab within seconds.
- **Grouping works**: `/boom/repeat?n=5` collapses into a single issue whose
  count increments, rather than five rows.
- **Stack traces render** with the crashing frame first, in-app frames
  emphasised, and source context lines around the crash.
- **PII scrubbing works**: `/boom/pii` sends an `Authorization` header, an
  `x-api-key`, a password, a card number and an email. All eight fields come
  back `[redacted]`, and the UI says so explicitly.
- **Pen-test tagging works**: an event sent while a run is open is tagged, hidden
  from the default Production filter, and visible under "During pen-test" with a
  neutral badge.
- `tsc --noEmit` passes; the Errors tab logs zero console errors.

### Two bugs found only by testing against a real SDK

1. **Sentry SDKs require a numeric DSN project id.** The registry originally
   seeded a friendly `trojan-demo` id, and every real SDK refused to initialise
   with `BadDsn`. Bugsink itself is lenient about this, so curl-level testing
   never caught it. DSN project ids are now numeric, with the slug kept as a
   separate display field.
2. **Node's built-in type stripping rejects constructor parameter properties.**
   Fixed by assigning the field longhand, which preserves the zero-install run
   path.

---

## Simplified or deferred, and why

Out of scope by the locked doc, and genuinely not built:

- **AI correlation with scan history (§7)** — explicitly deferred. No AI, no
  token metering, no billing code is touched anywhere in this feature.
- **DDoS detection** — explicitly out of scope.

Cut by me to hit tonight's bar, all of which need a decision before real
customers:

- **No real authentication.** The shim seeds exactly one project with a random
  key in `crash-analytics/.data/projects.json`. There is no user login, no
  per-customer project creation, and no key rotation. The DSN key is the only
  credential. Fine for localhost, **not fine for a public endpoint.**
- **No rate limiting or quotas.** §1 calls this out as the genuinely hard part.
  A customer in a crash loop would currently write unbounded events. Bugsink has
  a per-project `retention_max_event_count` (set to 10,000) which is the only
  backstop.
- **No symbolication / source maps.** Stack traces are shown as received. Minified
  JS will look minified. The research doc lists this as stage 5; it is unbuilt.
- **Storage is SQLite on one machine.** Fine for a demo, not a capacity plan.
- **The sidecar attribution index is approximate at scale.** Pen-test attribution
  scans at most the first 100 events of an issue and keeps at most 50,000 event
  records. Beyond that it defaults to `production`, which is the safe direction
  (a real bug is never hidden), but it is not exact.
- **Issue detail reads the latest event per issue** to get culprit, release and
  environment, because Bugsink's issue row has none of them. That is two backend
  calls per issue on the list, concurrency-capped at 8. Fine for tens of issues,
  would need denormalizing for thousands.
- **Resolve / mute / delete are not wired.** The types carry the fields and the
  backend supports it; there is no UI affordance.

---

## Things to decide before this goes past a demo

1. **Where the ingestion endpoint lives.** This is the big one, and §5 of the
   research doc already flagged it. A CLI that is briefly down costs a re-run.
   **An ingestion endpoint that is down loses production crash data permanently.**
   The shim currently runs on localhost. It needs a real always-on home, plus
   the uptime and on-call expectations that come with it. Nothing else in Trojan
   has that requirement today.

2. **Auth model.** Project keys need to be minted per customer and tied to a
   Trojan account. Right now there is one seeded key and no login.

3. **Bugsink vs GlitchTip.** Bugsink was chosen tonight because it stood up
   without Docker in two minutes. It is genuinely good, and the adapter boundary
   means switching is cheap, but the licence and support model are worth a look
   before shipping it inside a commercial product.

4. **PII policy.** Scrubbing is implemented and demonstrable, which is a real
   trust asset worth showing off. But §5's point stands: this needs a privacy
   policy update and probably DPA language before the first real customer sends
   production data through it. Worth noting the Python SDK captures frame-local
   variables by default (the Node SDK does not), which is a large PII surface
   the scrubber handles but which should be understood.

5. **Whether this pulls focus from launch.** §5's last risk. This is now a new
   always-on service to operate while Phase 7 is still pending.

---

## Notes and gotchas

- **`crash-analytics/runtime.json` and `.data/` are gitignored**, so a fresh
  clone must run `setup.sh`. Deleting `.data/projects.json` regenerates the DSN
  key, which invalidates any DSN already pasted into a customer app.
- **The desktop app renders blank in a plain browser.** It gates its whole render
  on a Tauri store call (`if (!profileLoaded) return null`), which throws outside
  Tauri. This is **pre-existing on `develop`, not caused by this work** — I
  confirmed HEAD behaves identically. Use `npm run tauri dev`. (For automated UI
  testing, stubbing `window.__TAURI_INTERNALS__` makes it render in a browser;
  that is how the Errors tab was visually verified.)
- **`ui/dist/.gitkeep` is missing from git**, so a cold `go build ./...` fails
  with `pattern all:ui/dist: no matching files found`. `.gitignore` whitelists
  the file but it was never committed. Pre-existing, left alone because `ui/` has
  its own `.gitignore` and there may be a reason. One-line fix when someone wants it.
- **Pen-test muting is wired into the real DAST path.** `cmd/trojan/main.go`
  opens the window before the Nuclei baseline and closes it when the agent loop
  returns; the SIGINT/SIGTERM handler closes it too, so a cancelled run cannot
  leave the Errors tab silently filtering real errors forever. All calls are
  best-effort with a 750ms timeout and no-op when the shim is not running.
- **This machine ran out of disk during the build** because `~/.npm/_cacache` had
  grown to 15GB. It was cleared (npm regenerates it automatically). Worth
  knowing if it recurs.

---

## Commits on this branch

```
Add crash-analytics storage backend setup (Bugsink, no Docker)
Add Trojan Errors API contract
Mute pen-test noise in Errors during agentic DAST runs
Add Trojan Errors ingestion + read shim
Add standalone Errors tab to the desktop app
Add sample breakable app, run scripts, and setup guide
```
