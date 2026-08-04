import { useEffect, useState } from 'react'
import { LiveRunView } from './LiveRunView'
import { RunSummary } from './RunSummary'
import { FindingsList } from './FindingsList'
import { FindingDetail } from './FindingDetail'
import { useAgenticRun } from '@/hooks/useAgenticRun'
import { getLatestScan } from '@/api'
import type { Finding, ScanResult } from '@/types'

// AgenticReport is the "Penetration Testing" surface shown when an agentic run
// is (or was) active. It streams the live run, then lets the user cross into the
// findings once it completes.
export function AgenticReport() {
  const run = useAgenticRun(true)
  const [scan, setScan] = useState<ScanResult | null>(null)
  const [view, setView] = useState<'run' | 'findings'>('run')
  const [selected, setSelected] = useState<Finding | null>(null)

  // Load findings up front (the server starts with the Nuclei baseline) and
  // refetch when the run reaches a terminal state — that's when the CLI has
  // merged + triaged the agent's findings into the scan.
  useEffect(() => {
    getLatestScan().then(setScan).catch(() => {})
  }, [])
  useEffect(() => {
    if (run.status === 'complete' || run.status === 'error') {
      getLatestScan().then(setScan).catch(() => {})
    }
  }, [run.status])

  const targetUrl = scan?.project_path ?? ''

  async function reload() {
    try {
      setScan(await getLatestScan())
    } catch {
      // ignore
    }
  }

  return (
    <div className="min-h-screen bg-background text-foreground">
      <header className="border-b border-border">
        <div className="max-w-3xl mx-auto px-8 py-5 flex items-center gap-2">
          <img src="/logo.png" alt="Trojan" className="h-14 w-auto" />
          <span className="text-xs font-medium uppercase tracking-widest text-muted-foreground border border-border rounded px-1.5 py-0.5">
            PEN TEST
          </span>
        </div>
      </header>

      <main className="max-w-3xl mx-auto px-8 py-12">
        {view === 'run' ? (
          <LiveRunView
            targetUrl={targetUrl}
            run={run}
            onViewFindings={scan ? () => setView('findings') : undefined}
          />
        ) : selected ? (
          <FindingDetail
            finding={selected}
            onBack={() => setSelected(null)}
            onAction={() => { setSelected(null); reload() }}
          />
        ) : (
          <div>
            <RunSummary
              findings={scan?.findings ?? []}
              summary={run.summary}
              onBackToRun={() => setView('run')}
            />
            {scan && scan.findings.filter(f => f.Status === 'open').length > 0 ? (
              <FindingsList findings={scan.findings} onSelect={setSelected} />
            ) : (
              <p className="text-sm text-muted-foreground py-12 text-center">
                No confirmed findings — the agent completed without surfacing an exploitable issue.
              </p>
            )}
          </div>
        )}
      </main>
    </div>
  )
}
