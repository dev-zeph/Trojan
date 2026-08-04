import type { Finding } from '@/types'

type Verdict = NonNullable<Finding['Verdict']>

const styles: Record<Verdict, { label: string; cls: string }> = {
  confirmed:    { label: 'Confirmed',    cls: 'text-red-500 border-red-500/40 bg-red-500/10' },
  needs_manual: { label: 'Needs review', cls: 'text-yellow-600 dark:text-yellow-400 border-yellow-500/40 bg-yellow-500/10' },
  likely_fp:    { label: 'Likely FP',    cls: 'text-muted-foreground border-border bg-muted/40' },
}

// VerdictBadge renders the agentic-DAST false-positive triage verdict.
// Renders nothing when a finding hasn't been triaged (free tier / triage skipped).
export function VerdictBadge({ verdict, confidence }: { verdict?: string; confidence?: number }) {
  if (!verdict || !(verdict in styles)) return null
  const s = styles[verdict as Verdict]
  return (
    <span
      className={`inline-flex items-center gap-1 text-[10px] font-medium uppercase tracking-widest rounded-full border px-2 py-0.5 ${s.cls}`}
    >
      {s.label}
      {typeof confidence === 'number' && confidence > 0 && (
        <span className="opacity-60">{Math.round(confidence * 100)}%</span>
      )}
    </span>
  )
}
