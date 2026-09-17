// Trojan Errors — normalized shapes (CONTRACT.md §B "Types").
//
// These are the ONLY shapes the desktop app ever sees. Nothing Bugsink-specific
// (friendly_id, calculated_type, digest_order, ...) may appear here or anywhere
// outside backends/bugsink.ts — swapping to GlitchTip must mean writing one new
// file in backends/ and changing nothing else.

export type TrojanSource = 'production' | 'dast_run'

export interface TrojanIssue {
  id: string
  shortId: string
  type: string
  value: string
  culprit: string
  count: number
  firstSeen: string
  lastSeen: string
  resolved: boolean
  muted: boolean
  source: TrojanSource
  release: string | null
  environment: string | null
}

export interface TrojanFrame {
  filename: string
  function: string
  lineno: number | null
  colno: number | null
  inApp: boolean
  contextLine: string | null
  preContext: string[]
  postContext: string[]
}

export interface TrojanRequest {
  method: string
  url: string
  headers: Record<string, string>
}

// Sentry SDKs (browser and node alike) attach these automatically to every
// event under `contexts.*` — the shim was discarding them. `browser`/`device`
// are typically null for server-side (node/python) events; `os` is populated
// for both.
export interface TrojanNamedContext {
  name: string
  version: string | null
}

export interface TrojanDeviceContext {
  family: string | null
  model: string | null
  brand: string | null
}

export interface TrojanEvent {
  id: string
  eventId: string
  timestamp: string
  level: string
  type: string
  value: string
  source: TrojanSource
  release: string | null
  environment: string | null
  serverName: string | null
  runtime: string | null
  browser: TrojanNamedContext | null
  os: TrojanNamedContext | null
  device: TrojanDeviceContext | null
  request: TrojanRequest | null
  frames: TrojanFrame[]
  scrubbed: string[]
}

// ---------------------------------------------------------------------------
// Backend adapter interface
// ---------------------------------------------------------------------------
//
// `source` is owned by the shim (it comes from our sidecar store, not from the
// storage backend), so adapters return everything *except* source.

export type BackendIssue = Omit<TrojanIssue, 'source'>
export type BackendEvent = Omit<TrojanEvent, 'source'>

export interface BackendEventSummary {
  /** backend-internal event row id, used to fetch the full event */
  id: string
  /** the Sentry event_id the SDK generated; our sidecar store's key */
  eventId: string
  timestamp: string
}

export interface ErrorsBackend {
  /** backend name as reported by GET /api/errors/health */
  readonly name: string
  /** never throws; false when the backend is unreachable or unhealthy */
  isReachable(): Promise<boolean>
  /** forward a (already scrubbed + tagged) Sentry envelope */
  ingestEnvelope(envelope: Buffer): Promise<void>
  listIssues(limit: number): Promise<BackendIssue[]>
  getIssue(id: string): Promise<BackendIssue | null>
  listIssueEvents(issueId: string, limit: number): Promise<BackendEventSummary[]>
  getEvent(eventId: string): Promise<BackendEvent | null>
  /** Idempotent: resolving an already-resolved issue is a no-op success, not an error. */
  resolveIssue(id: string): Promise<BackendIssue>
  /** Idempotent: reopening an already-open (unresolved) issue is a no-op success. */
  reopenIssue(id: string): Promise<BackendIssue>
  /** Idempotent: muting an already-muted issue is a no-op success, not an error. */
  muteIssue(id: string): Promise<BackendIssue>
  unmuteIssue(id: string): Promise<BackendIssue>
}
