// Bugsink storage adapter.
//
// This is the ONLY file that may mention Bugsink's own schema — friendly_id,
// calculated_type, digest_order, digested_event_count, /api/canonical/0/, and
// so on. Everything it hands back is already in Trojan shapes. Per the locked
// research doc §2 the backend choice is explicitly not a one-way door: adding
// backends/glitchtip.ts that satisfies ErrorsBackend must be the whole job.

import type { RuntimeConfig } from '../config.ts'
import { readScrubbed } from '../scrub.ts'
import type {
  BackendEvent,
  BackendEventSummary,
  BackendIssue,
  ErrorsBackend,
  TrojanDeviceContext,
  TrojanFrame,
  TrojanNamedContext,
  TrojanRequest,
} from '../types.ts'
import { fetchWithTimeout } from '../util.ts'

const API = '/api/canonical/0'
const READ_TIMEOUT_MS = 8_000
const INGEST_TIMEOUT_MS = 15_000
const HEALTH_TIMEOUT_MS = 3_000

// --- Bugsink wire shapes (private to this file) ------------------------------

interface BugsinkIssue {
  id: string
  friendly_id?: string
  project?: number
  digest_order?: number
  last_seen?: string
  first_seen?: string
  digested_event_count?: number
  stored_event_count?: number
  calculated_type?: string
  calculated_value?: string
  transaction?: string
  is_resolved?: boolean
  is_muted?: boolean
}

interface BugsinkEventRow {
  id: string
  event_id?: string
  issue?: string
  timestamp?: string
  ingested_at?: string
  digest_order?: number
  data?: Record<string, unknown>
}

interface BugsinkPage<T> {
  next?: string | null
  previous?: string | null
  results?: T[]
}

function isObj(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v)
}

function str(v: unknown): string | null {
  return typeof v === 'string' && v.length > 0 ? v : null
}

// --- normalization -----------------------------------------------------------

function normalizeIssue(raw: BugsinkIssue): BackendIssue {
  const now = new Date().toISOString()
  return {
    id: raw.id,
    shortId: raw.friendly_id ?? raw.id,
    type: raw.calculated_type ?? 'Error',
    value: raw.calculated_value ?? '',
    // Best-effort from the issue row alone; the read API upgrades this to a
    // real "file:line in fn" culprit from the latest event's frames.
    culprit: raw.transaction ?? '',
    count: raw.digested_event_count ?? raw.stored_event_count ?? 0,
    firstSeen: raw.first_seen ?? now,
    lastSeen: raw.last_seen ?? now,
    resolved: Boolean(raw.is_resolved),
    muted: Boolean(raw.is_muted),
    release: null,
    environment: null,
  }
}

function normalizeFrames(data: Record<string, unknown>): TrojanFrame[] {
  const exception = data['exception']
  const values = isObj(exception) ? exception['values'] : undefined
  if (!Array.isArray(values) || values.length === 0) return []

  // Sentry puts the most relevant (outermost cause) exception last.
  const primary = values[values.length - 1]
  if (!isObj(primary)) return []
  const stacktrace = primary['stacktrace']
  const frames = isObj(stacktrace) ? stacktrace['frames'] : undefined
  if (!Array.isArray(frames)) return []

  // Order is preserved verbatim: innermost/crashing frame stays LAST.
  return frames.filter(isObj).map((f): TrojanFrame => ({
    filename: str(f['filename']) ?? str(f['abs_path']) ?? str(f['module']) ?? '',
    function: str(f['function']) ?? '',
    lineno: typeof f['lineno'] === 'number' ? f['lineno'] : null,
    colno: typeof f['colno'] === 'number' ? f['colno'] : null,
    inApp: f['in_app'] === true,
    contextLine: typeof f['context_line'] === 'string' ? f['context_line'] : null,
    preContext: Array.isArray(f['pre_context']) ? f['pre_context'].map(String) : [],
    postContext: Array.isArray(f['post_context']) ? f['post_context'].map(String) : [],
  }))
}

function normalizeRequest(data: Record<string, unknown>): TrojanRequest | null {
  const request = data['request']
  if (!isObj(request)) return null
  const headers: Record<string, string> = {}
  const rawHeaders = request['headers']
  if (isObj(rawHeaders)) {
    for (const [k, v] of Object.entries(rawHeaders)) {
      headers[k] = typeof v === 'string' ? v : JSON.stringify(v)
    }
  }
  return {
    method: str(request['method']) ?? '',
    url: str(request['url']) ?? '',
    headers,
  }
}

function normalizeRuntime(data: Record<string, unknown>): string | null {
  const contexts = data['contexts']
  if (!isObj(contexts)) return null
  const runtime = contexts['runtime']
  if (!isObj(runtime)) return null
  const name = str(runtime['name'])
  const version = str(runtime['version'])
  if (name && version) return `${name} ${version}`
  return str(runtime['description']) ?? name ?? version
}

// Sentry SDKs attach `contexts.browser` / `contexts.os` / `contexts.device`
// automatically — this was always in the raw envelope, just never read past
// `contexts.runtime`. Browser/device are typically absent on server-side
// (node/python) events; that's expected, not a bug.
function namedContext(data: Record<string, unknown>, key: string): TrojanNamedContext | null {
  const contexts = data['contexts']
  if (!isObj(contexts)) return null
  const ctx = contexts[key]
  if (!isObj(ctx)) return null
  const name = str(ctx['name'])
  if (!name) return null
  return { name, version: str(ctx['version']) }
}

function deviceContext(data: Record<string, unknown>): TrojanDeviceContext | null {
  const contexts = data['contexts']
  if (!isObj(contexts)) return null
  const device = contexts['device']
  if (!isObj(device)) return null
  const family = str(device['family'])
  const model = str(device['model'])
  const brand = str(device['brand'])
  if (!family && !model && !brand) return null
  return { family, model, brand }
}

function primaryException(data: Record<string, unknown>): { type: string; value: string } {
  const exception = data['exception']
  const values = isObj(exception) ? exception['values'] : undefined
  if (Array.isArray(values) && values.length > 0) {
    const primary = values[values.length - 1]
    if (isObj(primary)) {
      return {
        type: str(primary['type']) ?? 'Error',
        value: str(primary['value']) ?? '',
      }
    }
  }
  const message = data['message']
  if (typeof message === 'string') return { type: 'Message', value: message }
  if (isObj(message) && typeof message['formatted'] === 'string') {
    return { type: 'Message', value: message['formatted'] }
  }
  return { type: 'Error', value: '' }
}

function normalizeEvent(row: BugsinkEventRow): BackendEvent {
  const data = row.data ?? {}
  const { type, value } = primaryException(data)
  return {
    id: row.id,
    eventId: row.event_id ?? row.id,
    timestamp: row.timestamp ?? row.ingested_at ?? new Date().toISOString(),
    level: str(data['level']) ?? 'error',
    type,
    value,
    release: str(data['release']),
    environment: str(data['environment']),
    serverName: str(data['server_name']),
    runtime: normalizeRuntime(data),
    browser: namedContext(data, 'browser'),
    os: namedContext(data, 'os'),
    device: deviceContext(data),
    request: normalizeRequest(data),
    frames: normalizeFrames(data),
    scrubbed: readScrubbed(data),
  }
}

// --- adapter -----------------------------------------------------------------

export class BugsinkBackend implements ErrorsBackend {
  readonly name = 'bugsink'

  // Written out longhand rather than as a constructor parameter property:
  // Node's built-in type stripping is strip-only and rejects `constructor(private x)`,
  // and running this service with plain `node` (no tsx, no install) is worth more
  // than the shorthand.
  private readonly cfg: RuntimeConfig

  constructor(cfg: RuntimeConfig) {
    this.cfg = cfg
  }

  private get authHeaders(): Record<string, string> {
    return { Authorization: `Bearer ${this.cfg.backendApiToken}` }
  }

  private async readJson<T>(path: string, timeoutMs = READ_TIMEOUT_MS): Promise<T> {
    const url = path.startsWith('http') ? path : `${this.cfg.backendUrl}${path}`
    const res = await fetchWithTimeout(url, { headers: this.authHeaders }, timeoutMs)
    if (!res.ok) {
      throw new Error(`bugsink ${res.status} ${res.statusText} for ${url}`)
    }
    return (await res.json()) as T
  }

  async isReachable(): Promise<boolean> {
    try {
      // The issues endpoint exercises URL + token + project id in one shot.
      const url =
        `${this.cfg.backendUrl}${API}/issues/?project=` +
        encodeURIComponent(this.cfg.backendProjectId)
      const res = await fetchWithTimeout(url, { headers: this.authHeaders }, HEALTH_TIMEOUT_MS)
      return res.ok
    } catch {
      return false
    }
  }

  async ingestEnvelope(envelope: Buffer): Promise<void> {
    const url = `${this.cfg.backendUrl}/api/${this.cfg.backendProjectId}/envelope/`
    const res = await fetchWithTimeout(
      url,
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-sentry-envelope',
          'X-Sentry-Auth': `Sentry sentry_key=${this.cfg.backendPublicKey}, sentry_version=7`,
        },
        body: new Uint8Array(envelope),
      },
      INGEST_TIMEOUT_MS,
    )
    if (!res.ok) {
      const body = await res.text().catch(() => '')
      throw new Error(`bugsink ingest ${res.status} ${res.statusText}: ${body.slice(0, 500)}`)
    }
  }

  async listIssues(limit: number): Promise<BackendIssue[]> {
    // `project` is required by Bugsink and must be the integer project id.
    const query = new URLSearchParams({
      project: this.cfg.backendProjectId,
      sort: 'last_seen',
      order: 'desc',
    })

    const collected: BackendIssue[] = []
    let next: string | null = `${API}/issues/?${query.toString()}`
    let pages = 0

    // Bugsink paginates by cursor and `next` is a full URL. Follow it only far
    // enough to satisfy `limit`; never walk the whole history.
    while (next && collected.length < limit && pages < 20) {
      const page: BugsinkPage<BugsinkIssue> = await this.readJson<BugsinkPage<BugsinkIssue>>(next)
      for (const raw of page.results ?? []) {
        collected.push(normalizeIssue(raw))
        if (collected.length >= limit) break
      }
      next = page.next ?? null
      pages++
    }

    return collected
  }

  async getIssue(id: string): Promise<BackendIssue | null> {
    try {
      const raw = await this.readJson<BugsinkIssue>(`${API}/issues/${encodeURIComponent(id)}/`)
      return raw && raw.id ? normalizeIssue(raw) : null
    } catch {
      // Bugsink has no per-issue detail route in every build; fall back to the
      // list, which is authoritative for the same fields.
      const all = await this.listIssues(200)
      return all.find(i => i.id === id) ?? null
    }
  }

  async listIssueEvents(issueId: string, limit: number): Promise<BackendEventSummary[]> {
    const page = await this.readJson<BugsinkPage<BugsinkEventRow>>(
      `${API}/events/?issue=${encodeURIComponent(issueId)}`,
    )
    return (page.results ?? []).slice(0, limit).map(row => ({
      id: row.id,
      eventId: row.event_id ?? row.id,
      timestamp: row.timestamp ?? row.ingested_at ?? new Date().toISOString(),
    }))
  }

  async getEvent(eventId: string): Promise<BackendEvent | null> {
    const row = await this.readJson<BugsinkEventRow>(
      `${API}/events/${encodeURIComponent(eventId)}/`,
    )
    return row && row.id ? normalizeEvent(row) : null
  }

  // Bugsink's issue-action endpoints (verified against the installed package's
  // issues/api_views.py, not guessed): POST .../issues/{id}/{action}/, Bearer
  // auth, no body. They 400 on a state the issue is already in (e.g. resolving
  // an already-resolved issue) — Trojan treats that as success, since the
  // caller's desired end state is already true, and re-fetches the issue so
  // the response is still accurate rather than stale.
  private async postAction(id: string, action: 'resolve' | 'reopen' | 'mute' | 'unmute'): Promise<BackendIssue> {
    const url = `${this.cfg.backendUrl}${API}/issues/${encodeURIComponent(id)}/${action}/`
    const res = await fetchWithTimeout(url, { method: 'POST', headers: this.authHeaders }, READ_TIMEOUT_MS)

    if (res.ok) {
      return normalizeIssue((await res.json()) as BugsinkIssue)
    }
    if (res.status === 400) {
      const current = await this.getIssue(id)
      if (current) return current
    }
    const body = await res.text().catch(() => '')
    throw new Error(`bugsink ${action} ${res.status} ${res.statusText}: ${body.slice(0, 300)}`)
  }

  async resolveIssue(id: string): Promise<BackendIssue> {
    return this.postAction(id, 'resolve')
  }

  async reopenIssue(id: string): Promise<BackendIssue> {
    return this.postAction(id, 'reopen')
  }

  async muteIssue(id: string): Promise<BackendIssue> {
    return this.postAction(id, 'mute')
  }

  async unmuteIssue(id: string): Promise<BackendIssue> {
    return this.postAction(id, 'unmute')
  }
}

export function createBugsinkBackend(cfg: RuntimeConfig): ErrorsBackend {
  return new BugsinkBackend(cfg)
}
