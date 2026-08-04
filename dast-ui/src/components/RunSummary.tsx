import type { Finding } from '@/types'

interface Props {
  findings: Finding[]
  summary: string
  onBackToRun?: () => void
}

// RunSummary (§10.2 screen 5) — the outcome header shown above the findings
// list once a run completes: a verdict breakdown plus the agent's summary.
export function RunSummary({ findings, summary, onBackToRun }: Props) {
  const open = findings.filter(f => f.Status === 'open')
  const confirmed = open.filter(f => f.Verdict === 'confirmed').length
  const needsReview = open.filter(f => f.Verdict === 'needs_manual').length
  const likelyFp = open.filter(f => f.Verdict === 'likely_fp').length

  return (
    <div className="space-y-5 border-b border-border pb-8 mb-8">
      <div className="flex items-center justify-between">
        <h2 className="text-xs uppercase tracking-widest text-muted-foreground">Results</h2>
        {onBackToRun && (
          <button
            onClick={onBackToRun}
            className="text-xs text-muted-foreground underline underline-offset-4 hover:text-foreground transition-colors"
          >
            ← Run timeline
          </button>
        )}
      </div>

      <div className="flex flex-wrap items-baseline gap-x-8 gap-y-2">
        <Stat value={open.length} label="findings" />
        {confirmed > 0 && <Stat value={confirmed} label="confirmed" cls="text-red-500" />}
        {needsReview > 0 && <Stat value={needsReview} label="need review" cls="text-yellow-600 dark:text-yellow-400" />}
        {likelyFp > 0 && <Stat value={likelyFp} label="likely FP" cls="text-muted-foreground" />}
      </div>

      {summary && <p className="text-sm text-foreground/70 leading-relaxed max-w-2xl">{summary}</p>}
    </div>
  )
}

function Stat({ value, label, cls }: { value: number; label: string; cls?: string }) {
  return (
    <div className="flex items-baseline gap-2">
      <span className={`text-2xl font-bold tabular-nums ${cls ?? 'text-foreground'}`}>{value}</span>
      <span className="text-xs uppercase tracking-widest text-muted-foreground">{label}</span>
    </div>
  )
}
