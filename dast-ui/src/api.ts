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

// Attack-graph wire types — mirror internal/dast/agent (§9.3).
export type NodeStatus = 'untested' | 'testing' | 'safe' | 'vulnerable' | 'chained'
export type NodeType = 'endpoint' | 'finding' | 'credential' | 'data'
export type EdgeKind = 'chain' | 'dataflow' | 'trust'

export interface HandlerRef {
  file: string
  line: number
  symbol?: string
}

export interface GraphNode {
  id: string
  type: NodeType
  label: string
  method?: string
  status: NodeStatus
  severity?: string
  attack?: string
  handler?: HandlerRef
  evidence?: string
}

export interface GraphEdge {
  from: string
  to: string
  kind: EdgeKind
  confirmed: boolean
  rationale?: string
}

// GreyBoxSummary is the structural read of a handler, rendered as chips (§6.6).
export interface GreyBoxSummary {
  has_auth_check: boolean
  sanitizes_input: boolean
  raw_query: boolean
  reflects_input: boolean
}

// PendingApproval mirrors agent.PendingAction — a state-changing action gated for
// operator review (§8). Carries everything the approval card needs to show.
export interface PendingApproval {
  id: number
  tool: string
  method: string
  url: string
  body?: string
  identity?: string
  reason: string
  step?: number
}

// AgentEvent mirrors internal/server.AgentEvent — one streamed run action.
export interface AgentEvent {
  type: 'step' | 'text' | 'tool_use' | 'tool_result' | 'finding' | 'graph' | 'stopped' | 'finish' | 'run'
    | 'approval_request' | 'approval_resolved'
  step?: number
  tool?: string
  detail?: string
  status?: RunStatus
  // Structured payload for the two-surface UI (§9); set by type.
  node?: GraphNode
  edge?: GraphEdge
  source?: HandlerRef
  summary?: GreyBoxSummary
  mode?: string
  // §8 human-in-the-loop: the gated action (approval_request) / resolved one
  // (approval_resolved, with `approved` = the decision).
  approval?: PendingApproval
  approved?: boolean
}

// decideApproval sends an operator's §8 decision to the reverse channel. The run
// loop executes the vetted action (approve) or skips it (deny) and reports back.
export async function decideApproval(id: number, approve: boolean, note?: string): Promise<void> {
  const res = await fetch(`${BASE}/dast/approval`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ id, approve, note: note ?? '' }),
  })
  if (!res.ok) throw new Error((await safeError(res)) ?? 'could not send decision')
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
