import { useEffect, useState } from 'react'
import { Dashboard } from './components/Dashboard'
import { FindingsList } from './components/FindingsList'
import { FindingDetail } from './components/FindingDetail'
import { getLatestScan } from './api'
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
  const { dark, toggle } = useDarkMode()

  async function loadScan() {
    try {
      const data = await getLatestScan()
      setScan(data)
    } catch {
      setError('Could not load scan results.')
    }
  }

  useEffect(() => { loadScan() }, [])

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

      {/* Header */}
      <header className="border-b border-border">
        <div className="max-w-5xl mx-auto px-8 py-5 flex items-center justify-between">
          <div className="flex items-center gap-8">
            <span className="font-bold tracking-tight text-sm uppercase">Trojan</span>
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
            onSelect={setSelected}
          />
        )}
      </main>
    </div>
  )
}
