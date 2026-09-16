# Trojan Errors — internal API contract

This is the integration contract between the three pieces of the crash-analytics
feature. It is the source of truth; if an implementation disagrees with this
document, the implementation is wrong.

```
customer's running app
  │  real @sentry/node SDK, Trojan DSN
  ▼
Trojan Errors shim          backend/src/errors/   :3002   <- Trojan code
  │  auth, PII scrub, DAST-mute tag, forward
  ▼
Bugsink                     crash-analytics/      :8000   <- OSS, not customer-visible
  │  fingerprint, group, store
  ▼
Trojan Errors shim          read API, normalized into Trojan shapes
  ▼
Trojan desktop app          desktop/src/App.tsx, view "errors"
```

Bugsink is an implementation detail. It is never shown to a customer, never
linked to from Trojan's UI, and every field the desktop renders comes from the
shim's normalized shapes below — not from Bugsink's own schema. Swapping in
GlitchTip later means rewriting one adapter file, not the UI.

---

## Ports

| Port | Process | Notes |
|------|---------|-------|
| 8000 | Bugsink | storage backend, internal only |
| 3002 | Trojan Errors shim | ingestion + read API |
| 3003 | sample breakable app | demo target |
| 1420 | desktop app (vite) | existing Tauri dev port |

The shim is deliberately NOT port 3001 — that's the existing `backend/src/index.ts`,
which cannot boot in this environment (it imports `supabase.ts`, which throws at
module load without `SUPABASE_URL` / `SUPABASE_SERVICE_ROLE_KEY`, and there is no
`.env`). The Errors shim must have **zero** dependency on Supabase or any secret.

---

## Config: `crash-analytics/runtime.json`

Written by `setup.sh`, gitignored. The shim reads it at boot.

```json
{
  "backend": "bugsink",
  "backendUrl": "http://localhost:8000",
  "backendProjectId": "1",
  "backendPublicKey": "844d04...",
  "backendDsn": "http://844d04...@localhost:8000/1",
  "backendApiToken": "40653336a7ea364176cc20b2f1d2e9de3894f23b"
}
```

---

## A. Ingestion API (customer-facing, Sentry wire protocol)

The shim speaks enough of the Sentry protocol that an unmodified `@sentry/node`
(or any Sentry SDK) works against it. This is what keeps us honest to the locked
"don't build client SDKs" decision.

```
POST /api/:projectId/envelope/     <- what modern SDKs use
POST /api/:projectId/store/        <- legacy single-event endpoint
```

Auth: public key from either the `sentry_key` query param or the
`X-Sentry-Auth: Sentry sentry_key=...` header. Must match the Trojan project key.

The Trojan DSN handed to customers is therefore:

```
http://<trojanProjectKey>@localhost:3002/<trojanProjectId>
```

Behaviour:
1. Resolve + authenticate the project key. Unknown key → `401`.
2. Parse the envelope (newline-delimited JSON: header, then item-header/item pairs).
3. For each `event` item: **scrub PII**, then stamp DAST-mute tags.
4. Re-serialize and forward to Bugsink's envelope endpoint using Bugsink's own DSN.
5. Record `{ sentryEventId, source, dastRunId, receivedAt }` in the shim's sidecar
   store so the read API can attribute issues to production vs pen-test.
6. Always respond `200 {"id": "<event_id>"}` quickly. Never block the customer's
   app on our storage; a reporting failure must not become a second crash.

Non-`event` items (sessions, transactions, client reports) are accepted and
forwarded unchanged, but not indexed.

### PII scrubbing (applied before anything is stored)

Remove: `authorization`, `cookie`, `set-cookie`, `x-api-key`, `proxy-authorization`
headers; any key matching `/pass|secret|token|auth|key|cred|session/i` in request
data, extra, or frame-local vars; and value-level redaction of email addresses,
long bearer-ish tokens, and card-shaped digit runs in messages and frame vars.
Replace with `[redacted]` and append the field path to a `trojan_scrubbed` list on
the event so the UI can be honest about what was dropped.

### DAST-mute tagging (research doc §3a — tag, never drop)

Shim keeps in-memory + on-disk DAST state. When a pen-test run is active, an
incoming event is stamped `tags.trojan_source = "dast_run"` plus
`tags.trojan_dast_run_id`; otherwise `tags.trojan_source = "production"`.

Events are **never dropped**. The desktop app's default filter hides `dast_run`
issues; a filter chip reveals them.

Issue-level attribution rule: an issue counts as `dast_run` only if **every**
recorded event for it was during a pen-test. Any single production event makes
the whole issue `production`. This guarantees a real bug can never be hidden by
pen-test noise.

```
POST /api/errors/dast/start   { "runId": "...", "target": "..." }  -> { ok, runId }
POST /api/errors/dast/stop    { "runId": "..." }                   -> { ok }
GET  /api/errors/dast/status                                        -> { active, runId, target, startedAt }
```

---

## B. Read API (consumed by the desktop app)

All responses `application/json`, permissive CORS (`Access-Control-Allow-Origin: *`)
so the Vite dev server on :1420 can call it directly.

### `GET /api/errors/health`
```json
{ "ok": true, "backend": "bugsink", "backendReachable": true, "projectConfigured": true }
```
Must return `200` with `backendReachable: false` rather than erroring when Bugsink
is down, so the UI can render a useful "backend not running" state.

### `GET /api/errors/config`
```json
{
  "dsn": "http://<key>@localhost:3002/<id>",
  "ingestUrl": "http://localhost:3002/api/<id>/envelope/",
  "projectId": "trojan-demo",
  "projectName": "Trojan Demo",
  "backend": "bugsink"
}
```
Powers the copy-paste setup panel in the Errors tab.

### `GET /api/errors/issues?filter=production|dast|all&limit=50`
Default `filter=production`.
```json
{
  "issues": [ TrojanIssue, ... ],
  "counts": { "production": 3, "dast": 1, "total": 4 }
}
```
`counts` always reflects all three regardless of the active filter, so the UI can
label its filter chips.

### `GET /api/errors/issues/:id`
```json
{ "issue": TrojanIssue, "latestEvent": TrojanEvent }
```

### `GET /api/errors/issues/:id/events?limit=20`
```json
{ "events": [ { "id", "eventId", "timestamp", "source" }, ... ] }
```

### Types

```ts
type TrojanSource = "production" | "dast_run";

interface TrojanIssue {
  id: string;            // opaque; use for the detail route
  shortId: string;       // human label, e.g. "TROJAN-ERRORS-1"
  type: string;          // "TypeError"
  value: string;         // "Cannot read properties of undefined (reading 'id')"
  culprit: string;       // "routes/checkout.js:42 in applyDiscount", "" if unknown
  count: number;         // total events in this group
  firstSeen: string;     // ISO 8601
  lastSeen: string;      // ISO 8601
  resolved: boolean;
  muted: boolean;
  source: TrojanSource;
  release: string | null;
  environment: string | null;
}

interface TrojanFrame {
  filename: string;
  function: string;
  lineno: number | null;
  colno: number | null;
  inApp: boolean;
  contextLine: string | null;
  preContext: string[];
  postContext: string[];
}

interface TrojanEvent {
  id: string;
  eventId: string;
  timestamp: string;
  level: string;              // "error" | "warning" | ...
  type: string;
  value: string;
  source: TrojanSource;
  release: string | null;
  environment: string | null;
  serverName: string | null;
  runtime: string | null;     // "node v25.9.0"
  request: { method: string; url: string; headers: Record<string,string> } | null;
  frames: TrojanFrame[];      // Sentry order: innermost/crashing frame LAST
  scrubbed: string[];         // field paths that were redacted
}
```

Empty state is `{"issues": [], "counts": {...zeros}}` with `200` — never a 404.
