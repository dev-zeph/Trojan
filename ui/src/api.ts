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
