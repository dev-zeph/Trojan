// Trojan Errors shim — entrypoint.
//
// Two surfaces on one port (CONTRACT.md):
//   A. Sentry-protocol ingestion, so an unmodified @sentry/node works against a
//      Trojan DSN. This is what keeps us on the locked "adopt, don't build"
//      decision (research doc §2) instead of inventing a wire protocol.
//   B. A Trojan-native read API the desktop Errors tab consumes. Nothing
//      backend-specific escapes through it.
//
// Deliberately imports nothing from ../supabase.ts or ../auth.ts: those throw at
// module load without env vars that do not exist in this environment. This
// service boots with zero secrets, which is why it is a separate entrypoint from
// backend/src/index.ts rather than another route on it.

import { createServer, type IncomingMessage, type ServerResponse } from 'node:http'

import {
  PORT,
  authenticateProject,
  defaultProject,
  loadRegistry,
  loadRuntime,
  trojanDsn,
  trojanIngestUrl,
} from './config.ts'
import { createBugsinkBackend } from './backends/bugsink.ts'
import { currentTagging, getDastState, startDastRun, stopDastRun, tagEvent } from './dast.ts'
import { scrubEvent } from './scrub.ts'
import {
  decodeBody,
  envelopeFromEvent,
  extractSentryKey,
  normalizeEventId,
  parseEnvelope,
  serializeEnvelope,
  type Envelope,
} from './sentry.ts'
import { flushNow, lookupEvent, recordEvent } from './store.ts'
import type { ErrorsBackend, TrojanIssue, TrojanSource } from './types.ts'
import { culpritFromFrames, mapLimit } from './util.ts'

// How many of an issue's events we look at when deciding production vs pen-test.
// Bounded on purpose: an issue with 50k events must not cost 50k lookups.
const ATTRIBUTION_EVENT_SCAN = 100
// Per-issue backend lookups run concurrently but capped, so a 50-issue page
// doesn't serialize into minutes or stampede the backend.
const HYDRATE_CONCURRENCY = 8
const DEFAULT_ISSUE_LIMIT = 50

const runtime = loadRuntime()
const backend: ErrorsBackend = createBugsinkBackend(runtime)

// ── HTTP helpers ──────────────────────────────────────────────────────────

function cors(res: ServerResponse): void {
  res.setHeader('Access-Control-Allow-Origin', '*')
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
  res.setHeader('Access-Control-Allow-Headers', '*')
  res.setHeader('Access-Control-Max-Age', '86400')
}

function sendJson(res: ServerResponse, status: number, body: unknown): void {
  const payload = JSON.stringify(body)
  res.statusCode = status
  res.setHeader('Content-Type', 'application/json')
  res.end(payload)
}

function readBodyRaw(req: IncomingMessage): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = []
    req.on('data', chunk => chunks.push(chunk as Buffer))
    req.on('end', () => resolve(Buffer.concat(chunks)))
    req.on('error', reject)
  })
}

// ── B. Read API ───────────────────────────────────────────────────────────

/**
 * Decide whether an issue is production traffic or pen-test noise.
 *
 * Research doc §3a: tag, never drop. An issue only counts as pen-test noise if
 * EVERY event we have a record for happened during a run. A single production
 * event makes the whole issue production, so a real bug can never be hidden
 * behind pen-test traffic. Events we have no record for (ingested before the
 * shim existed, or evicted from the sidecar) default to production for the same
 * reason: when in doubt, show it.
 */
function attributeSource(eventIds: readonly string[]): TrojanSource {
  if (eventIds.length === 0) return 'production'
  for (const id of eventIds) {
    const record = lookupEvent(id)
    if (!record || record.source === 'production') return 'production'
  }
  return 'dast_run'
}

/**
 * Fill in the fields the storage backend's issue row cannot provide.
 *
 * Bugsink's issue row has no culprit/release/environment, so a real
 * "file:line in fn" culprit means reading the latest full event. That is two
 * backend calls per issue (event summaries for attribution, then one fat
 * event), which is why this is concurrency-capped and page-scoped.
 */
async function hydrateIssue(issue: Omit<TrojanIssue, 'source'>): Promise<TrojanIssue> {
  let source: TrojanSource = 'production'
  let culprit = issue.culprit
  let release = issue.release
  let environment = issue.environment

  try {
    const summaries = await backend.listIssueEvents(issue.id, ATTRIBUTION_EVENT_SCAN)
    source = attributeSource(summaries.map(s => normalizeEventId(s.eventId)))

    // Newest first, so [0] is the latest occurrence.
    const sorted = [...summaries].sort((a, b) => b.timestamp.localeCompare(a.timestamp))
    const latest = sorted[0]
    if (latest) {
      const event = await backend.getEvent(latest.id)
      if (event) {
        if (!culprit) culprit = culpritFromFrames(event.frames)
        release = event.release
        environment = event.environment
      }
    }
  } catch (err) {
    // A hydration failure must degrade to a usable row, not a 500.
    console.error(`[errors] could not hydrate issue ${issue.id}:`, String(err))
  }

  return { ...issue, culprit, release, environment, source }
}

async function handleIssues(url: URL, res: ServerResponse): Promise<void> {
  const filter = url.searchParams.get('filter') ?? 'production'
  const limit = Number(url.searchParams.get('limit') ?? DEFAULT_ISSUE_LIMIT)

  const raw = await backend.listIssues(Number.isFinite(limit) && limit > 0 ? limit : DEFAULT_ISSUE_LIMIT)
  const hydrated = await mapLimit(raw, HYDRATE_CONCURRENCY, issue => hydrateIssue(issue))

  // Counts always describe the whole page, regardless of the active filter, so
  // the UI can label its filter chips without a second request.
  const counts = {
    production: hydrated.filter(i => i.source === 'production').length,
    dast: hydrated.filter(i => i.source === 'dast_run').length,
    total: hydrated.length,
  }

  const issues =
    filter === 'all'
      ? hydrated
      : filter === 'dast'
        ? hydrated.filter(i => i.source === 'dast_run')
        : hydrated.filter(i => i.source === 'production')

  sendJson(res, 200, { issues, counts })
}

async function handleIssueDetail(id: string, res: ServerResponse): Promise<void> {
  const raw = await backend.getIssue(id)
  if (!raw) {
    sendJson(res, 404, { error: 'issue not found' })
    return
  }

  const issue = await hydrateIssue(raw)

  let latestEvent = null
  try {
    const summaries = await backend.listIssueEvents(id, ATTRIBUTION_EVENT_SCAN)
    const sorted = [...summaries].sort((a, b) => b.timestamp.localeCompare(a.timestamp))
    const latest = sorted[0]
    if (latest) {
      const event = await backend.getEvent(latest.id)
      if (event) {
        const record = lookupEvent(normalizeEventId(event.eventId))
        latestEvent = { ...event, source: record?.source ?? 'production' }
      }
    }
  } catch (err) {
    console.error(`[errors] could not load latest event for ${id}:`, String(err))
  }

  sendJson(res, 200, { issue, latestEvent })
}

async function handleIssueEvents(id: string, url: URL, res: ServerResponse): Promise<void> {
  const limit = Number(url.searchParams.get('limit') ?? 20)
  const summaries = await backend.listIssueEvents(id, Number.isFinite(limit) && limit > 0 ? limit : 20)
  const events = summaries.map(s => ({
    id: s.id,
    eventId: s.eventId,
    timestamp: s.timestamp,
    source: lookupEvent(normalizeEventId(s.eventId))?.source ?? 'production',
  }))
  sendJson(res, 200, { events })
}

// ── A. Ingestion ──────────────────────────────────────────────────────────

/**
 * Scrub + tag every event item in the envelope, record it in the sidecar index,
 * and rewrite the envelope header's dsn to point at the storage backend.
 * Returns the event id to acknowledge to the SDK.
 */
function prepareEnvelope(env: Envelope): string {
  const tagging = currentTagging()
  let eventId = normalizeEventId(env.header.event_id)

  for (const item of env.items) {
    if (item.header.type !== 'event') continue

    let event: Record<string, unknown>
    try {
      event = JSON.parse(item.payload.toString('utf8')) as Record<string, unknown>
    } catch {
      continue // not JSON we understand; forward it untouched
    }

    scrubEvent(event)
    tagEvent(event, tagging)

    const itemEventId = normalizeEventId((event['event_id'] as string) ?? eventId)
    if (itemEventId) {
      eventId = itemEventId
      recordEvent(itemEventId, {
        source: tagging.source,
        dastRunId: tagging.dastRunId,
        receivedAt: new Date().toISOString(),
      })
    }

    // serializeEnvelope recomputes `length` from this payload, so a size change
    // from scrubbing/tagging cannot truncate the event at the backend.
    item.payload = Buffer.from(JSON.stringify(event), 'utf8')
  }

  env.header.dsn = runtime.backendDsn
  return eventId
}

/** Forward without making the customer's app wait. Failures are logged, not thrown. */
function forward(env: Envelope): void {
  const body = serializeEnvelope(env)
  void backend.ingestEnvelope(body).catch((err: unknown) => {
    console.error('[errors] forward to storage backend failed:', String(err))
  })
}

async function handleIngest(
  req: IncomingMessage,
  res: ServerResponse,
  url: URL,
  projectId: string,
  kind: 'envelope' | 'store',
): Promise<void> {
  const key = extractSentryKey(url, req.headers)
  const project = authenticateProject(projectId, key)
  if (!project) {
    sendJson(res, 401, { error: 'invalid project id or key' })
    return
  }

  const raw = await readBodyRaw(req)
  const body = decodeBody(raw, req.headers['content-encoding'])

  let env: Envelope
  try {
    if (kind === 'envelope') {
      env = parseEnvelope(body)
    } else {
      // Legacy /store/: a bare event JSON. Wrap it so one path handles both.
      const event = JSON.parse(body.toString('utf8')) as Record<string, unknown>
      env = envelopeFromEvent({ event_id: event['event_id'] as string | undefined }, event)
    }
  } catch (err) {
    sendJson(res, 400, { error: `malformed payload: ${String(err)}` })
    return
  }

  const eventId = prepareEnvelope(env)

  // Acknowledge first. A storage failure must never become a second crash in
  // the customer's app, and must never add latency to their request path.
  sendJson(res, 200, { id: eventId })

  forward(env)
}

// ── Routing ───────────────────────────────────────────────────────────────

const ISSUE_EVENTS_RE = /^\/api\/errors\/issues\/([^/]+)\/events\/?$/
const ISSUE_DETAIL_RE = /^\/api\/errors\/issues\/([^/]+)\/?$/
// Matched only AFTER every /api/errors/* route, or "errors" reads as a project id.
const INGEST_RE = /^\/api\/([^/]+)\/(envelope|store)\/?$/

async function route(req: IncomingMessage, res: ServerResponse): Promise<void> {
  const url = new URL(req.url ?? '/', `http://localhost:${PORT}`)
  const path = url.pathname
  const method = req.method ?? 'GET'

  if (method === 'OPTIONS') {
    res.statusCode = 204
    res.end()
    return
  }

  // --- health ---
  if (path === '/api/errors/health' && method === 'GET') {
    // Must be 200 with backendReachable:false when the backend is down, so the
    // desktop can render a useful "not running" state instead of an error.
    const reachable = await backend.isReachable()
    sendJson(res, 200, {
      ok: true,
      backend: backend.name,
      backendReachable: reachable,
      projectConfigured: loadRegistry().length > 0,
    })
    return
  }

  // --- config (powers the copy-paste setup guide) ---
  if (path === '/api/errors/config' && method === 'GET') {
    const project = defaultProject()
    sendJson(res, 200, {
      dsn: trojanDsn(project),
      ingestUrl: trojanIngestUrl(project),
      projectId: project.id,
      projectSlug: project.slug,
      projectName: project.name,
      // Suggested values for the setup snippet, so it is fully copy-paste
      // rather than leaving the developer to invent them.
      suggestedRelease: `${project.slug}@1.0.0`,
      suggestedEnvironment: 'production',
      backend: backend.name,
    })
    return
  }

  // --- DAST mute state (research doc §3a) ---
  if (path === '/api/errors/dast/status' && method === 'GET') {
    const state = getDastState()
    sendJson(res, 200, state)
    return
  }

  if (path === '/api/errors/dast/start' && method === 'POST') {
    const body = JSON.parse((await readBodyRaw(req)).toString('utf8') || '{}') as {
      runId?: string
      target?: string
    }
    const runId = body.runId ?? `dast-${Date.now()}`
    startDastRun(runId, body.target ?? null)
    sendJson(res, 200, { ok: true, runId })
    return
  }

  if (path === '/api/errors/dast/stop' && method === 'POST') {
    const body = JSON.parse((await readBodyRaw(req)).toString('utf8') || '{}') as { runId?: string }
    const { stopped } = stopDastRun(body.runId ?? null)
    sendJson(res, 200, { ok: true, stopped })
    return
  }

  // --- issues ---
  if (path === '/api/errors/issues' && method === 'GET') {
    await handleIssues(url, res)
    return
  }

  const eventsMatch = ISSUE_EVENTS_RE.exec(path)
  if (eventsMatch?.[1] && method === 'GET') {
    await handleIssueEvents(decodeURIComponent(eventsMatch[1]), url, res)
    return
  }

  const detailMatch = ISSUE_DETAIL_RE.exec(path)
  if (detailMatch?.[1] && method === 'GET') {
    await handleIssueDetail(decodeURIComponent(detailMatch[1]), res)
    return
  }

  // --- ingestion (must come last) ---
  const ingestMatch = INGEST_RE.exec(path)
  if (ingestMatch?.[1] && ingestMatch[2] && method === 'POST') {
    await handleIngest(req, res, url, decodeURIComponent(ingestMatch[1]), ingestMatch[2] as 'envelope' | 'store')
    return
  }

  sendJson(res, 404, { error: 'not found' })
}

const server = createServer((req, res) => {
  cors(res)
  route(req, res).catch((err: unknown) => {
    console.error('[errors] unhandled request error:', String(err))
    if (!res.headersSent) sendJson(res, 500, { error: 'internal error' })
    else res.end()
  })
})

server.listen(PORT, () => {
  const project = defaultProject()
  console.log(`Trojan Errors shim listening on http://localhost:${PORT}`)
  console.log(`  storage backend : ${backend.name} at ${runtime.backendUrl}`)
  console.log(`  project         : ${project.name} (${project.id})`)
  console.log(`  customer DSN    : ${trojanDsn(project)}`)
})

for (const signal of ['SIGINT', 'SIGTERM'] as const) {
  process.on(signal, () => {
    flushNow() // don't lose anything sitting in the sidecar's debounce window
    server.close(() => process.exit(0))
    // Don't hang forever on keep-alive connections.
    setTimeout(() => process.exit(0), 2000).unref()
  })
}
