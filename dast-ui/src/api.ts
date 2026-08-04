import type { ScanResult } from './types'

const BASE = '/api'

export async function getLatestScan(): Promise<ScanResult> {
  const res = await fetch(`${BASE}/scans/latest`)
  if (!res.ok) throw new Error('Failed to load scan results')
  return res.json()
}

export async function reviewFinding(id: string): Promise<void> {
  await fetch(`${BASE}/findings/${id}/resolve`, { method: 'POST' })
}

export async function suppressFinding(id: string): Promise<void> {
  await fetch(`${BASE}/findings/${id}/suppress`, { method: 'POST' })
}

export interface AuthStatus {
  loggedIn: boolean
  isPro: boolean
  plan?: string
  email?: string
}

export async function getAuthStatus(): Promise<AuthStatus> {
  try {
    const res = await fetch(`${BASE}/auth/status`)
    if (!res.ok) return { loggedIn: false, isPro: false }
    return res.json()
  } catch {
    return { loggedIn: false, isPro: false }
  }
}

// ── Agentic penetration test (Phase 5 §10) ───────────────────────────────────

export type RunStatus = 'idle' | 'running' | 'complete' | 'error'

// AgentEvent mirrors internal/server.AgentEvent — one streamed run action.
export interface AgentEvent {
  type: 'step' | 'text' | 'tool_use' | 'tool_result' | 'finding' | 'stopped' | 'finish' | 'run'
  step?: number
  tool?: string
  detail?: string
  status?: RunStatus
}

export interface AgenticStatus {
  status: RunStatus
  events: number
}

export async function getAgenticStatus(): Promise<AgenticStatus> {
  try {
    const res = await fetch(`${BASE}/dast/agentic/status`)
    if (!res.ok) return { status: 'idle', events: 0 }
    return res.json()
  } catch {
    return { status: 'idle', events: 0 }
  }
}

// agenticEventsURL is the SSE endpoint the run view subscribes to. It replays a
// buffer on connect (so a late subscriber catches up) then tails live events.
export const agenticEventsURL = `${BASE}/dast/agentic/events`

// ── Consent gate (Phase 2 §4) ─────────────────────────────────────────────────

export interface ConsentStatus {
  allowed: boolean
  isLocal: boolean
  verified: boolean
  domain: string
  method?: string
}

export async function getConsentStatus(url: string): Promise<ConsentStatus> {
  const res = await fetch(`${BASE}/dast/consent/status?url=${encodeURIComponent(url)}`)
  if (!res.ok) throw new Error((await safeError(res)) ?? 'consent status failed')
  return res.json()
}

export interface MintResult {
  domain: string
  token: string
  isLocal: boolean
  txtPrefix: string
  wellKnownPath: string
  metaName: string
}

export async function mintConsent(url: string): Promise<MintResult> {
  const res = await fetch(`${BASE}/dast/consent/mint`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url }),
  })
  if (!res.ok) throw new Error((await safeError(res)) ?? 'could not mint token')
  return res.json()
}

export type VerifyMethod = 'dns' | 'file' | 'meta'

export interface VerifyResult {
  verified: boolean
  error?: string
  domain?: string
  method?: string
}

export async function verifyConsent(url: string, method: VerifyMethod): Promise<VerifyResult> {
  const res = await fetch(`${BASE}/dast/consent/verify`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url, method }),
  })
  // Verification failures come back as 200 { verified:false, error }.
  if (!res.ok) return { verified: false, error: (await safeError(res)) ?? 'verification failed' }
  return res.json()
}

async function safeError(res: Response): Promise<string | undefined> {
  try {
    const body = await res.json()
    return typeof body?.error === 'string' ? body.error : undefined
  } catch {
    return undefined
  }
}
