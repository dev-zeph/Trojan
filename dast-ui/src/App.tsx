import { useEffect, useState } from 'react'
import { FindingsList } from './components/FindingsList'
import { FindingDetail } from './components/FindingDetail'
import { getLatestScan, getAuthStatus } from './api'
import type { AuthStatus } from './api'
import type { Finding, ScanResult } from './types'

export default function App() {
  const [scan, setScan] = useState<ScanResult | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [selected, setSelected] = useState<Finding | null>(null)
  const [auth, setAuth] = useState<AuthStatus | null>(null)

  useEffect(() => {
    const root = document.documentElement
    const mq = window.matchMedia('(prefers-color-scheme: dark)')
    mq.matches ? root.classList.add('dark') : root.classList.remove('dark')
    const handler = (e: MediaQueryListEvent) =>
      e.matches ? root.classList.add('dark') : root.classList.remove('dark')
    mq.addEventListener('change', handler)
    return () => mq.removeEventListener('change', handler)
  }, [])

  useEffect(() => {
    getLatestScan()
      .then(setScan)
      .catch(() => setError('Could not load scan results.'))
    getAuthStatus().then(setAuth)
  }, [])

  async function reload() {
    try {
      const data = await getLatestScan()
      setScan(data)
    } catch {
      // ignore reload errors
    }
  }

  if (error) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <p className="text-sm text-muted-foreground">{error}</p>
      </div>
    )
  }

  if (!scan) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <p className="text-sm text-muted-foreground">Loading...</p>
      </div>
    )
  }

  const openCount = scan.findings.filter(f => f.Status === 'open').length

  return (
    <div className="min-h-screen bg-background text-foreground">

      {/* Auth banner */}
      {auth && !auth.loggedIn && (
        <div className="border-b border-border bg-muted/40">
          <div className="max-w-5xl mx-auto px-8 py-2.5 flex items-center justify-between">
            <p className="text-xs text-muted-foreground">
              Unlock AI explanations and fix suggestions with Trojan Pro.
            </p>
            <a
              href="https://trojancli.com/login"
              target="_blank"
              rel="noopener noreferrer"
              className="text-xs font-medium underline underline-offset-4 hover:text-muted-foreground transition-colors"
            >
              Log in or sign up →
            </a>
          </div>
        </div>
      )}
      {auth?.loggedIn && !auth.isPro && (
        <div className="border-b border-border bg-muted/40">
          <div className="max-w-5xl mx-auto px-8 py-2.5 flex items-center justify-between">
            <p className="text-xs text-muted-foreground">
              You're on the free plan. Upgrade to Pro to unlock AI explanations.
            </p>
            <a
              href="https://trojancli.com/pricing"
              target="_blank"
              rel="noopener noreferrer"
              className="text-xs font-medium underline underline-offset-4 hover:text-muted-foreground transition-colors"
            >
              Upgrade to Pro →
            </a>
          </div>
        </div>
      )}
      {auth?.loggedIn && auth.isPro && (
        <div className="border-b border-border bg-muted/40">
          <div className="max-w-5xl mx-auto px-8 py-2.5 flex items-center justify-between">
            <p className="text-xs text-muted-foreground">
              <span className="text-foreground font-medium">{auth.email}</span>
              {' '}· You're the pro.
            </p>
            <span className="text-xs font-medium uppercase tracking-widest text-foreground">
              {auth.plan ?? 'Pro'}
            </span>
          </div>
        </div>
      )}

      {/* Header */}
      <header className="border-b border-border">
        <div className="max-w-5xl mx-auto px-8 py-5 flex items-center justify-between">
          <div className="flex items-center gap-6">
            <div className="flex items-center gap-2">
              <span className="font-bold text-lg tracking-tight">Trojan</span>
              <span className="text-xs font-medium uppercase tracking-widest text-muted-foreground border border-border rounded px-1.5 py-0.5">
                DAST
              </span>
            </div>
            {!selected && (
              <div className="flex items-center gap-2 text-xs text-muted-foreground">
                <span className="font-mono truncate max-w-xs">{scan.project_path}</span>
                <span>·</span>
                <span>{openCount} finding{openCount !== 1 ? 's' : ''}</span>
              </div>
            )}
          </div>
          <time className="text-xs text-muted-foreground" dateTime={scan.timestamp}>
            {new Date(scan.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
          </time>
        </div>
      </header>

      {/* Main */}
      <main className="max-w-5xl mx-auto px-8 py-16">
        {selected ? (
          <FindingDetail
            finding={selected}
            onBack={() => setSelected(null)}
            onAction={() => { setSelected(null); reload() }}
          />
        ) : openCount === 0 ? (
          <div className="py-24 text-center space-y-3">
            <p className="text-sm font-medium text-foreground">No runtime vulnerabilities found</p>
            <p className="text-xs text-muted-foreground">
              {scan.project_path} passed the DAST scan.
            </p>
          </div>
        ) : (
          <FindingsList
            findings={scan.findings}
            onSelect={setSelected}
          />
        )}
      </main>
    </div>
  )
}
