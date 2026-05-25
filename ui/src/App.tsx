import { useEffect, useState } from 'react'
import { Dashboard } from './components/Dashboard'
import { FindingsList } from './components/FindingsList'
import { FindingDetail } from './components/FindingDetail'
import { getLatestScan, getAuthStatus } from './api'
import type { AuthStatus } from './api'
import type { Finding, ScanResult } from './types'

type View = 'dashboard' | 'findings'

function useDarkMode() {
  const [dark, setDark] = useState(() =>
    window.matchMedia('(prefers-color-scheme: dark)').matches
  )

  useEffect(() => {
    const root = document.documentElement
    dark ? root.classList.add('dark') : root.classList.remove('dark')
  }, [dark])

  return { dark, toggle: () => setDark(d => !d) }
}

export default function App() {
  const [scan, setScan] = useState<ScanResult | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [view, setView] = useState<View>('dashboard')
  const [selected, setSelected] = useState<Finding | null>(null)
  const [auth, setAuth] = useState<AuthStatus | null>(null)
  const { dark, toggle } = useDarkMode()

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

      {/* Login / upgrade banner */}
      {auth && !auth.loggedIn && (
        <div className="border-b border-border bg-muted/40">
          <div className="max-w-5xl mx-auto px-8 py-2.5 flex items-center justify-between">
            <p className="text-xs text-muted-foreground">
              Unlock AI explanations and fix suggestions with Trojan Pro.
            </p>
            <a
              href="https://trojan.dev"
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
              href="https://trojan.dev/pricing"
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
          <div className="flex items-center gap-8">
            <img src="/logo.png" alt="Trojan" className="h-14 w-auto" />
            {!selected && (
              <nav className="flex gap-6">
                {(['dashboard', 'findings'] as View[]).map(v => (
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
                    {v === 'findings' && ` (${scan.findings.length})`}
                  </button>
                ))}
              </nav>
            )}
          </div>

          <button
            onClick={toggle}
            className="text-xs text-muted-foreground hover:text-foreground transition-colors uppercase tracking-widest"
          >
            {dark ? 'Light' : 'Dark'}
          </button>
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
        ) : (
          <FindingsList
            findings={scan.findings}
            lockedCount={scan.locked_count ?? 0}
            onSelect={setSelected}
          />
        )}
      </main>
    </div>
  )
}
