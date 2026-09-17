import { useEffect, useState } from 'react'
import { Dashboard } from './components/Dashboard'
import { FindingsList } from './components/FindingsList'
import { FindingDetail } from './components/FindingDetail'
import { DependencyDashboard } from './components/DependencyDashboard'
import { getLatestScan, getAuthStatus, subscribeToScanEvents } from './api'
import type { AuthStatus } from './api'
import type { Finding, ScanResult } from './types'
import { ExternalLink } from './components/ExternalLink'

type View = 'dashboard' | 'findings' | 'dependencies'

export default function App() {
  const [scan, setScan] = useState<ScanResult | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [view, setView] = useState<View>('dashboard')
  const [selected, setSelected] = useState<Finding | null>(null)
  const [auth, setAuth] = useState<AuthStatus | null>(null)
  const [rescanning, setRescanning] = useState(false)

  async function loadScan() {
    try {
      const data = await getLatestScan()
      setScan(data)
    } catch {
      setError('Could not load scan results.')
    }
  }

  useEffect(() => {
    loadScan()
    getAuthStatus().then(setAuth)

    // Subscribe to --watch re-scan events. The server sends scan_complete
    // over SSE after every file-change triggered re-scan.
    const unsubscribe = subscribeToScanEvents(async () => {
      setRescanning(true)
      await loadScan()
      setRescanning(false)
    })

    return unsubscribe
  }, [])

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

  return (
    <div className="min-h-screen bg-background text-foreground">

      {/* Account banner.
          There is no "upgrade to unlock" state any more: every finding at every
          severity is already visible to everyone, because scanning runs locally
          and costs us nothing. Signing in is about AI work, which is paid for
          with tokens. */}
      {auth && !auth.loggedIn && (
        <div className="border-b border-border bg-muted/40">
          <div className="max-w-5xl mx-auto px-8 py-2.5 flex items-center justify-between">
            <p className="text-xs text-muted-foreground">
              Sign in for AI explanations and fix steps, 500 free tokens a month.
            </p>
            <ExternalLink
              href="https://trojancli.com/login"
              className="text-xs font-medium underline underline-offset-4 hover:text-muted-foreground transition-colors"
            >
              Log in or sign up →
            </ExternalLink>
          </div>
        </div>
      )}
      {auth?.loggedIn && (
        <div className="border-b border-border bg-muted/40">
          <div className="max-w-5xl mx-auto px-8 py-2.5 flex items-center justify-between">
            <p className="text-xs text-muted-foreground">
              <span className="text-foreground font-medium">{auth.email}</span>
              {' '}· signed in
            </p>
            <ExternalLink
              href="https://trojancli.com/dashboard"
              className="text-xs font-medium underline underline-offset-4 hover:text-muted-foreground transition-colors"
            >
              Token balance →
            </ExternalLink>
          </div>
        </div>
      )}

      {/* Header */}
      <header className="border-b border-border">
        <div className="max-w-5xl mx-auto px-8 py-5 flex items-center justify-between">
          <div className="flex items-center gap-8">
            <img src="/logo.png" alt="Trojan" className="h-14 w-auto" />
            {!selected && (
              <nav className="flex gap-6">
                {(['dashboard', 'findings', 'dependencies'] as View[]).map(v => (
                  <button
                    key={v}
                    onClick={() => setView(v)}
                    className={`text-sm capitalize transition-colors ${
                      view === v
                        ? 'text-foreground'
                        : 'text-muted-foreground hover:text-foreground'
                    }`}
                  >
                    {v}
                    {v === 'findings' && ` (${scan.findings.filter(f => f.Status === 'open').length})`}
                    {v === 'dependencies' && scan.packages != null && ` (${scan.packages.length})`}
                  </button>
                ))}
              </nav>
            )}
            {rescanning && (
              <span className="text-xs text-muted-foreground animate-pulse">
                Rescanning…
              </span>
            )}
          </div>

        </div>
      </header>

      {/* Main */}
      <main className="max-w-5xl mx-auto px-8 py-16">
        {selected ? (
          <FindingDetail
            finding={selected}
            onBack={() => setSelected(null)}
            onAction={() => { setSelected(null); loadScan() }}
          />
        ) : view === 'dashboard' ? (
          <Dashboard
            scan={scan}
            onViewFindings={() => setView('findings')}
            onSelectFinding={setSelected}
          />
        ) : view === 'dependencies' ? (
          <DependencyDashboard packages={scan.packages ?? []} />
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
