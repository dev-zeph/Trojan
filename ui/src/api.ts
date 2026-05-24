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
