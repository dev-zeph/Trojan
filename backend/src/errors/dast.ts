// DAST-mute state — research doc §3a, "Tag, don't drop".
//
// When Trojan's pen-test agent is actively attacking a target it will
// legitimately throw errors. Those must not read as "your app is broken", but
// they must also never be discarded: a real production bug that happens to fire
// during the pen-test window has to survive. So we tag, and the read API filters.

import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { DATA_DIR } from './config.ts'
import type { TrojanSource } from './types.ts'

const STATE_PATH = join(DATA_DIR, 'dast.json')

export interface DastState {
  active: boolean
  runId: string | null
  target: string | null
  startedAt: string | null
}

const EMPTY: DastState = { active: false, runId: null, target: null, startedAt: null }

// In-memory is the hot path (one lookup per ingested event); disk is just so
// the flag survives a shim restart mid-run.
let state: DastState = { ...EMPTY }
let loaded = false

function persist(): void {
  try {
    if (!existsSync(DATA_DIR)) mkdirSync(DATA_DIR, { recursive: true })
    writeFileSync(STATE_PATH, JSON.stringify(state, null, 2))
  } catch (err) {
    console.error('[errors] failed to persist DAST state:', String(err))
  }
}

export function loadDastState(): DastState {
  if (loaded) return state
  loaded = true
  try {
    if (existsSync(STATE_PATH)) {
      const parsed = JSON.parse(readFileSync(STATE_PATH, 'utf8')) as Partial<DastState>
      state = {
        active: Boolean(parsed.active),
        runId: parsed.runId ?? null,
        target: parsed.target ?? null,
        startedAt: parsed.startedAt ?? null,
      }
    }
  } catch (err) {
    console.error('[errors] DAST state unreadable, starting clean:', String(err))
    state = { ...EMPTY }
  }
  return state
}

export function getDastState(): DastState {
  return { ...loadDastState() }
}

export function startDastRun(runId: string, target: string | null): DastState {
  loadDastState()
  state = {
    active: true,
    runId,
    target: target ?? null,
    startedAt: new Date().toISOString(),
  }
  persist()
  return { ...state }
}

/**
 * Stop a run. A runId that does not match the active run is a no-op on the
 * state (a late stop from a previous run must not cancel the current one).
 */
export function stopDastRun(runId: string | null): { state: DastState; stopped: boolean } {
  loadDastState()
  if (!state.active) return { state: { ...state }, stopped: false }
  if (runId && state.runId && runId !== state.runId) {
    return { state: { ...state }, stopped: false }
  }
  state = { ...EMPTY }
  persist()
  return { state: { ...state }, stopped: true }
}

/** The tag stamped onto every incoming event. */
export function currentTagging(): { source: TrojanSource; dastRunId: string | null } {
  const s = loadDastState()
  return s.active && s.runId
    ? { source: 'dast_run', dastRunId: s.runId }
    : { source: 'production', dastRunId: null }
}

/**
 * Stamp `tags.trojan_source` (+ `tags.trojan_dast_run_id`) onto an event
 * payload in place. Tags are chosen deliberately: every Sentry-protocol backend
 * preserves them verbatim, unlike arbitrary top-level keys.
 */
export function tagEvent(
  event: Record<string, unknown>,
  tagging: { source: TrojanSource; dastRunId: string | null },
): void {
  const existing = event['tags']
  const tags: Record<string, unknown> =
    typeof existing === 'object' && existing !== null && !Array.isArray(existing)
      ? (existing as Record<string, unknown>)
      : {}

  tags['trojan_source'] = tagging.source
  if (tagging.dastRunId) tags['trojan_dast_run_id'] = tagging.dastRunId
  else delete tags['trojan_dast_run_id']

  event['tags'] = tags
}
