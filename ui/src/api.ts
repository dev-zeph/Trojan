import type { ScanResult } from './types'

const BASE = '/api'

export async function getLatestScan(): Promise<ScanResult> {
  const res = await fetch(`${BASE}/scans/latest`)
  if (!res.ok) throw new Error('Failed to load scan results')
  return res.json()
}

export async function resolveFinding(id: string): Promise<void> {
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

/**
 * Subscribe to scan-complete events from the Go server (Server-Sent Events).
 * Returns a cleanup function — call it when the component unmounts.
 *
 * The server sends `data: scan_complete\n\n` after every --watch re-scan.
 * The caller should re-fetch /api/scans/latest in the onScanComplete callback.
 */
export function subscribeToScanEvents(onScanComplete: () => void): () => void {
  const es = new EventSource(`${BASE}/events`)

  es.onmessage = (e) => {
    if (e.data === 'scan_complete') {
      onScanComplete()
    }
  }

  // Non-fatal: if SSE isn't available (e.g. not in --watch mode) the
  // connection will simply not send any messages.
  es.onerror = () => {
    // Browsers auto-reconnect on error; nothing to do here.
  }

  return () => es.close()
}

// ── Authenticated testing identities (test accounts) ──────────────────────────
// Credentials the AI agent uses to log in and test pages behind a login, and to
// compare two accounts for IDOR (one account reading another's data). Stored
// locally (0600) by the Go backend and never leaves the machine. On read,
// password-like field values (key matches /pass|pwd|secret|token/i) come back as
// "" with login.secret_set = true, so the UI shows "password is set" without
// echoing it. Re-saving an empty password on an identity whose secret is already
// set preserves the stored value.
export interface IdentityLogin {
  url: string
  method?: 'POST'
  fields: { [field: string]: string }
  secret_set?: boolean
}

export interface Identity {
  name: string
  login?: IdentityLogin
  headers?: { [header: string]: string }
}

export async function getIdentities(url: string): Promise<Identity[]> {
  try {
    const res = await fetch(`${BASE}/identities?url=${encodeURIComponent(url)}`)
    if (!res.ok) return []
    const body = await res.json()
    return Array.isArray(body?.identities) ? body.identities : []
  } catch {
    return []
  }
}

export async function putIdentities(url: string, identities: Identity[]): Promise<Identity[]> {
  const res = await fetch(`${BASE}/identities?url=${encodeURIComponent(url)}`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ identities }),
  })
  if (!res.ok) throw new Error('Could not save test accounts')
  const body = await res.json()
  return Array.isArray(body?.identities) ? body.identities : []
}
