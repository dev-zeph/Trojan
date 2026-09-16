// Sidecar index: sentryEventId -> { source, dastRunId, receivedAt }.
//
// The storage backend groups and stores events; it does not know about Trojan's
// production-vs-pen-test distinction. Rather than round-trip a fat event payload
// per issue just to read one tag back, the shim keeps its own tiny index keyed
// by the Sentry event_id, written at ingest time.

import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { DATA_DIR } from './config.ts'
import { normalizeEventId } from './sentry.ts'
import type { TrojanSource } from './types.ts'

const STORE_PATH = join(DATA_DIR, 'events.json')
const FLUSH_DEBOUNCE_MS = 250
/** Ring-buffer cap so a crash loop cannot grow this file without bound. */
const MAX_RECORDS = 50_000

export interface EventRecord {
  source: TrojanSource
  dastRunId: string | null
  receivedAt: string
}

let index: Map<string, EventRecord> | null = null
let flushTimer: NodeJS.Timeout | null = null
let dirty = false

function load(): Map<string, EventRecord> {
  if (index) return index
  index = new Map()
  try {
    if (existsSync(STORE_PATH)) {
      const parsed = JSON.parse(readFileSync(STORE_PATH, 'utf8')) as Record<string, EventRecord>
      for (const [key, value] of Object.entries(parsed)) {
        if (value && typeof value === 'object') index.set(key, value)
      }
    }
  } catch (err) {
    console.error('[errors] sidecar store unreadable, starting empty:', String(err))
    index = new Map()
  }
  return index
}

function flush(): void {
  if (!dirty || !index) return
  dirty = false
  try {
    if (!existsSync(DATA_DIR)) mkdirSync(DATA_DIR, { recursive: true })
    const obj = Object.fromEntries(index)
    // Write-then-rename so a crash mid-write cannot leave a truncated file.
    const tmp = `${STORE_PATH}.tmp`
    writeFileSync(tmp, JSON.stringify(obj))
    renameSync(tmp, STORE_PATH)
  } catch (err) {
    console.error('[errors] failed to persist sidecar store:', String(err))
  }
}

function scheduleFlush(): void {
  dirty = true
  if (flushTimer) return
  flushTimer = setTimeout(() => {
    flushTimer = null
    flush()
  }, FLUSH_DEBOUNCE_MS)
  flushTimer.unref?.()
}

export function recordEvent(eventId: string, record: EventRecord): void {
  const key = normalizeEventId(eventId)
  if (!key) return
  const map = load()
  map.set(key, record)

  if (map.size > MAX_RECORDS) {
    // Map preserves insertion order — drop the oldest overflow.
    const excess = map.size - MAX_RECORDS
    let dropped = 0
    for (const k of map.keys()) {
      map.delete(k)
      if (++dropped >= excess) break
    }
  }

  scheduleFlush()
}

export function lookupEvent(eventId: string): EventRecord | undefined {
  return load().get(normalizeEventId(eventId))
}

export function storeSize(): number {
  return load().size
}

/** Flush synchronously on shutdown so nothing in the debounce window is lost. */
export function flushNow(): void {
  if (flushTimer) {
    clearTimeout(flushTimer)
    flushTimer = null
  }
  flush()
}
