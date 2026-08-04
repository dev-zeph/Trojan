import { useEffect, useState } from 'react'
import type { AgentEvent } from '@/api'
import type { RunState } from '@/hooks/useAgenticRun'

interface Props {
  targetUrl: string
  tier?: string
  run: RunState
  onViewFindings?: () => void
}

// LiveRunView is the centerpiece of the "Penetration Testing" UI (§10.2 screen
// 3): a timeline of the agent's actions as they stream, running counters, and a
// distinct terminal state for finished / stopped / errored runs.
export function LiveRunView({ targetUrl, tier, run, onViewFindings }: Props) {
  const elapsed = useElapsed(run.status === 'running')
  const terminal = run.status === 'complete' || run.status === 'error'

  return (
    <div className="max-w-3xl mx-auto space-y-10">
      {/* Header */}
      <div className="space-y-3">
        <div className="flex items-center gap-3">
          <StatusPill status={run.status} connected={run.connected} />
          {tier && (
            <span className="text-[10px] font-medium uppercase tracking-widest text-muted-foreground border border-border rounded px-1.5 py-0.5">
              {tier}
            </span>
          )}
        </div>
        <h1 className="text-2xl font-bold tracking-tight">Penetration test</h1>
        <a
          href={targetUrl}
          target="_blank"
          rel="noopener noreferrer"
          className="text-sm font-mono text-muted-foreground break-all hover:underline underline-offset-4"
        >
          {targetUrl}
        </a>
      </div>

      {/* Counters */}
      <div className="grid grid-cols-4 gap-px bg-border border border-border rounded overflow-hidden">
        <Counter label="Steps" value={String(run.steps)} />
        <Counter label="Probes" value={String(run.probes)} />
        <Counter label="Findings" value={String(run.findings)} />
        <Counter label="Elapsed" value={fmtElapsed(elapsed)} />
      </div>

      {/* Terminal banner */}
      {terminal && (
        <TerminalBanner run={run} onViewFindings={onViewFindings} />
      )}

      {/* Timeline */}
      <Timeline events={run.events} running={run.status === 'running'} />
    </div>
  )
}

function StatusPill({ status, connected }: { status: RunState['status']; connected: boolean }) {
  const map: Record<RunState['status'], { label: string; cls: string; live?: boolean }> = {
    idle: { label: 'Idle', cls: 'text-muted-foreground border-border bg-muted/40' },
    running: { label: connected ? 'Running' : 'Reconnecting…', cls: 'text-emerald-600 dark:text-emerald-400 border-emerald-500/40 bg-emerald-500/10', live: true },
    complete: { label: 'Complete', cls: 'text-emerald-600 dark:text-emerald-400 border-emerald-500/40 bg-emerald-500/10' },
    error: { label: 'Failed', cls: 'text-red-500 border-red-500/40 bg-red-500/10' },
  }
  const s = map[status]
  return (
    <span className={`inline-flex items-center gap-1.5 text-[10px] font-medium uppercase tracking-widest rounded-full border px-2 py-0.5 ${s.cls}`}>
      {s.live && <span className="w-1.5 h-1.5 rounded-full bg-current pulse-dot" />}
      {s.label}
    </span>
  )
}

function Counter({ label, value }: { label: string; value: string }) {
  return (
    <div className="bg-background px-4 py-3">
      <div className="text-[10px] uppercase tracking-widest text-muted-foreground">{label}</div>
      <div className="text-lg font-semibold tabular-nums mt-0.5">{value}</div>
    </div>
  )
}

function TerminalBanner({ run, onViewFindings }: { run: RunState; onViewFindings?: () => void }) {
  const isError = run.status === 'error'
  const stopped = run.stopReason !== ''
  return (
    <div
      className={`rounded border p-5 space-y-2 ${
        isError
          ? 'border-red-500/40 bg-red-500/10'
          : stopped
            ? 'border-yellow-500/40 bg-yellow-500/10'
            : 'border-emerald-500/40 bg-emerald-500/10'
      }`}
    >
      <p className="text-sm font-semibold">
        {isError
          ? 'Run failed'
          : stopped
            ? `Stopped — ${run.stopReason} (partial results)`
            : 'Run complete'}
      </p>
      {(run.summary || run.errorDetail) && (
        <p className="text-sm text-foreground/70 leading-relaxed">{run.errorDetail || run.summary}</p>
      )}
      {!isError && onViewFindings && (
        <button
          onClick={onViewFindings}
          className="text-xs font-medium underline underline-offset-4 hover:text-muted-foreground transition-colors"
        >
          View findings →
        </button>
      )}
    </div>
  )
}

function Timeline({ events, running }: { events: AgentEvent[]; running: boolean }) {
  // Drop 'run' lifecycle events — they're surfaced by the pill/banner, not the timeline.
  const rows = events.filter(e => e.type !== 'run')
  const lastIsStep = rows.length > 0 && rows[rows.length - 1].type === 'step'

  if (rows.length === 0) {
    return <SkeletonTimeline />
  }

  return (
    <div className="space-y-1">
      {rows.map((e, i) => (
        <TimelineRow key={i} event={e} />
      ))}
      {/* Reasoning shimmer while the model is thinking between actions. */}
      {running && lastIsStep && (
        <div className="flex items-center gap-2 pl-4 py-2 text-xs text-muted-foreground">
          <span className="shimmer inline-block w-24 h-3 rounded" aria-hidden />
          <span className="sr-only">Agent is reasoning</span>
          <span>thinking…</span>
        </div>
      )}
    </div>
  )
}

function TimelineRow({ event }: { event: AgentEvent }) {
  switch (event.type) {
    case 'step':
      return (
        <div className="pt-6 pb-1">
          <span className="text-[10px] uppercase tracking-widest text-muted-foreground">Step {event.step}</span>
        </div>
      )
    case 'text':
      return <p className="text-sm text-foreground/80 leading-relaxed pl-4">{event.detail}</p>
    case 'tool_use':
      return (
        <details className="pl-4 group probe-pulse">
          <summary className="text-sm cursor-pointer list-none flex items-center gap-2">
            <span className="text-muted-foreground">→</span>
            <span className="font-mono text-xs">{event.tool}</span>
            {event.detail && <span className="text-[10px] text-muted-foreground group-open:hidden">expand</span>}
          </summary>
          {event.detail && (
            <pre className="mt-2 ml-6 bg-muted rounded p-3 text-[11px] font-mono overflow-x-auto leading-relaxed whitespace-pre-wrap break-all">
              {event.detail}
            </pre>
          )}
        </details>
      )
    case 'tool_result':
      return (
        <p className="pl-10 text-xs font-mono text-muted-foreground break-all">
          {event.detail}
        </p>
      )
    case 'finding':
      return (
        <div className="reveal pl-4 py-2 flex items-center gap-2 border-l-2 border-emerald-500/50">
          <span className="text-emerald-600 dark:text-emerald-400 text-sm">✓</span>
          <span className="text-sm font-medium">{event.detail}</span>
        </div>
      )
    case 'stopped':
      return (
        <p className="pl-4 py-2 text-xs uppercase tracking-widest text-yellow-600 dark:text-yellow-400">
          stopped: {event.detail}
        </p>
      )
    default:
      return null
  }
}

function SkeletonTimeline() {
  return (
    <div className="space-y-3" aria-hidden>
      {[0, 1, 2].map(i => (
        <div key={i} className="flex items-center gap-3 pl-4">
          <span className="shimmer inline-block w-16 h-3 rounded" />
          <span className="shimmer inline-block h-3 rounded" style={{ width: `${60 - i * 12}%` }} />
        </div>
      ))}
    </div>
  )
}

// ── helpers ──

function useElapsed(running: boolean): number {
  const [ticks, setTicks] = useState(0)
  const [start] = useState(() => Date.now())
  useEffect(() => {
    if (!running) return
    const id = setInterval(() => setTicks(t => t + 1), 1000)
    return () => clearInterval(id)
  }, [running])
  // ticks referenced so the interval re-renders; value derived from wall clock.
  void ticks
  return Math.floor((Date.now() - start) / 1000)
}

function fmtElapsed(s: number): string {
  const m = Math.floor(s / 60)
  const sec = s % 60
  return m > 0 ? `${m}m ${sec}s` : `${sec}s`
}
