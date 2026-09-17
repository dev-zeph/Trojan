import { useEffect, useState } from 'react'
import { decideApproval } from '@/api'
import type { AgentEvent, GraphNode, PendingApproval } from '@/api'
import { graphCounts, type RunState } from '@/hooks/useAgenticRun'
import { AttackGraphView } from './AttackGraphView'
import { NodeDetail } from './NodeDetail'

interface Props {
  targetUrl: string
  tier?: string
  run: RunState
  onViewFindings?: () => void
}

// LiveRunView is the two-surface "Penetration Testing" run view (§9): a narrative
// stream (hypothesis → action → result → verdict) beside a live attack-coverage
// graph, with a click-through detail panel. Chat is linear; a chain is a graph —
// so both surfaces render the same run, one for reasoning, one for structure.
export function LiveRunView({ targetUrl, tier, run, onViewFindings }: Props) {
  const elapsed = useElapsed(run.status === 'running')
  const terminal = run.status === 'complete' || run.status === 'error'
  const counts = graphCounts(run.graph)
  const [selected, setSelected] = useState<GraphNode | null>(null)

  // Keep the selected node's data fresh as deltas update it (e.g. an endpoint
  // going untested → vulnerable while its detail panel is open).
  const selectedLive = selected ? run.graph.nodes[selected.id] ?? selected : null

  return (
    <div className="space-y-8">
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
        <a href={targetUrl} target="_blank" rel="noopener noreferrer"
          className="text-sm font-mono text-muted-foreground break-all hover:underline underline-offset-4">
          {targetUrl}
        </a>
      </div>

      {/* Counters */}
      <div className="grid grid-cols-5 gap-px bg-border border border-border rounded overflow-hidden">
        <Counter label="Steps" value={String(run.steps)} />
        <Counter label="Probes" value={String(run.probes)} />
        <Counter label="Coverage" value={`${counts.tested}/${counts.endpoints}`} />
        <Counter label="Vulnerable" value={String(counts.vulnerable)} accent={counts.vulnerable > 0} />
        <Counter label="Elapsed" value={fmtElapsed(elapsed)} />
      </div>

      {run.pendingApprovals.length > 0 && <ApprovalPanel approvals={run.pendingApprovals} />}

      {terminal && <TerminalBanner run={run} onViewFindings={onViewFindings} />}

      {/* Two surfaces: narrative + graph/detail */}
      <div className="grid lg:grid-cols-[1fr_minmax(340px,42%)] gap-6 items-start">
        <div className="min-w-0">
          <SurfaceLabel>Narrative</SurfaceLabel>
          <Timeline events={run.events} running={run.status === 'running'} />
        </div>
        <div className="min-w-0 lg:sticky lg:top-6">
          <SurfaceLabel>{selectedLive ? 'Node detail' : 'Attack surface'}</SurfaceLabel>
          <div className="h-[440px]">
            {selectedLive
              ? <NodeDetail node={selectedLive} onClose={() => setSelected(null)} />
              : <AttackGraphView graph={run.graph} selectedId={null} onSelect={setSelected} />}
          </div>
          <Legend />
        </div>
      </div>
    </div>
  )
}

function SurfaceLabel({ children }: { children: React.ReactNode }) {
  return <div className="text-[10px] uppercase tracking-widest text-muted-foreground mb-2">{children}</div>
}

function Legend() {
  const items: Array<[string, string]> = [
    ['untested', 'text-muted-foreground'],
    ['testing', 'text-yellow-500'],
    ['safe', 'text-emerald-600 dark:text-emerald-400'],
    ['vulnerable', 'text-red-500'],
  ]
  return (
    <div className="flex flex-wrap gap-x-4 gap-y-1 mt-2.5">
      {items.map(([label, cls]) => (
        <span key={label} className="inline-flex items-center gap-1.5 text-[10px] text-muted-foreground">
          <span className={`${cls} inline-block w-2 h-2 rounded-full`} style={{ background: 'currentColor' }} />
          {label}
        </span>
      ))}
      <span className="inline-flex items-center gap-1.5 text-[10px] text-muted-foreground">
        <span className="inline-block w-1.5 h-1.5" style={{ background: 'var(--source,#7c7cf0)' }} />
        source mapped
      </span>
      <span className="inline-flex items-center gap-1.5 text-[10px] text-muted-foreground">
        <svg width="16" height="6" aria-hidden><line x1="0" y1="3" x2="16" y2="3" className="text-red-500" stroke="currentColor" strokeWidth="2" strokeDasharray="4 3" /></svg>
        chain
      </span>
    </div>
  )
}

// ApprovalPanel is the §8 human-in-the-loop signal bar: a red-accented banner
// that surfaces every state-changing action the agent has queued for approval,
// with the exact request and the agent's reason (§8.4 — never a bare approve/deny).
// The run keeps testing other hypotheses while these wait.
function ApprovalPanel({ approvals }: { approvals: PendingApproval[] }) {
  return (
    <div className="border border-red-500/40 bg-red-500/5 rounded-lg overflow-hidden">
      <div className="flex items-center gap-2 px-4 py-2 border-b border-red-500/30 bg-red-500/10">
        <span className="w-1.5 h-1.5 rounded-full bg-red-500 pulse-dot" />
        <span className="text-[11px] font-semibold uppercase tracking-widest text-red-600 dark:text-red-400">
          {approvals.length} action{approvals.length > 1 ? 's' : ''} need your approval
        </span>
      </div>
      <div className="divide-y divide-border">
        {approvals.map(a => <ApprovalCard key={a.id} approval={a} />)}
      </div>
    </div>
  )
}

function ApprovalCard({ approval }: { approval: PendingApproval }) {
  const [submitting, setSubmitting] = useState<null | 'approve' | 'deny'>(null)
  const [error, setError] = useState('')

  async function decide(approve: boolean) {
    setSubmitting(approve ? 'approve' : 'deny')
    setError('')
    try {
      await decideApproval(approval.id, approve)
      // Success: leave the card disabled; the approval_resolved event removes it.
    } catch (e) {
      setError(e instanceof Error ? e.message : 'could not send decision')
      setSubmitting(null)
    }
  }

  return (
    <div className="p-4 space-y-2.5">
      <div className="flex items-center gap-2 flex-wrap">
        <span className="text-[10px] font-semibold uppercase tracking-widest text-red-600 dark:text-red-400 border border-red-500/40 rounded px-1.5 py-0.5">
          {approval.method}
        </span>
        <span className="font-mono text-xs break-all">{approval.url}</span>
        {approval.identity && (
          <span className="text-[10px] text-muted-foreground">as <span className="font-mono">{approval.identity}</span></span>
        )}
      </div>
      {approval.body && (
        <pre className="bg-muted rounded p-2 text-[11px] font-mono overflow-x-auto whitespace-pre-wrap break-all">{approval.body}</pre>
      )}
      <p className="text-xs text-muted-foreground leading-relaxed">
        <span className="text-foreground/70 font-medium">Why gated:</span> {approval.reason}
      </p>
      {error && <p className="text-xs text-red-500">{error}</p>}
      <div className="flex items-center gap-2 pt-0.5">
        <button
          type="button" disabled={submitting !== null}
          onClick={() => decide(true)}
          className="text-xs font-medium rounded px-3 py-1.5 bg-foreground text-background disabled:opacity-50 hover:opacity-90 transition">
          {submitting === 'approve' ? 'Approving…' : 'Approve'}
        </button>
        <button
          type="button" disabled={submitting !== null}
          onClick={() => decide(false)}
          className="text-xs font-medium rounded px-3 py-1.5 border border-border disabled:opacity-50 hover:bg-muted transition">
          {submitting === 'deny' ? 'Denying…' : 'Deny'}
        </button>
      </div>
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

function Counter({ label, value, accent }: { label: string; value: string; accent?: boolean }) {
  return (
    <div className="bg-background px-4 py-3">
      <div className="text-[10px] uppercase tracking-widest text-muted-foreground">{label}</div>
      <div className={`text-lg font-semibold tabular-nums mt-0.5 ${accent ? 'text-red-500' : ''}`}>{value}</div>
    </div>
  )
}

function TerminalBanner({ run, onViewFindings }: { run: RunState; onViewFindings?: () => void }) {
  const isError = run.status === 'error'
  const stopped = run.stopReason !== ''
  return (
    <div className={`rounded border p-5 space-y-2 ${isError ? 'border-red-500/40 bg-red-500/10' : stopped ? 'border-yellow-500/40 bg-yellow-500/10' : 'border-emerald-500/40 bg-emerald-500/10'}`}>
      <p className="text-sm font-semibold">
        {isError ? 'Run failed' : stopped ? `Stopped — ${run.stopReason} (partial results)` : 'Run complete'}
      </p>
      {(run.summary || run.errorDetail) && (
        <p className="text-sm text-foreground/70 leading-relaxed max-w-2xl whitespace-pre-line">{run.errorDetail || run.summary}</p>
      )}
      {!isError && onViewFindings && (
        <button onClick={onViewFindings} className="text-xs font-medium underline underline-offset-4 hover:text-muted-foreground transition-colors">
          View findings →
        </button>
      )}
    </div>
  )
}

function Timeline({ events, running }: { events: AgentEvent[]; running: boolean }) {
  // Graph deltas render on the other surface; drop them and lifecycle events here.
  const rows = events.filter(e => e.type !== 'run' && e.type !== 'graph')
  const lastIsStep = rows.length > 0 && rows[rows.length - 1].type === 'step'

  if (rows.length === 0) return <SkeletonTimeline />

  return (
    <div className="space-y-1">
      {rows.map((e, i) => <TimelineRow key={i} event={e} />)}
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
      return <div className="pt-6 pb-1"><span className="text-[10px] uppercase tracking-widest text-muted-foreground">Step {event.step}</span></div>
    case 'text':
      return <p className="text-sm text-foreground/80 leading-relaxed pl-4">{event.detail}</p>
    case 'tool_use':
      return (
        <details className="pl-4 group probe-pulse">
          <summary className="text-sm cursor-pointer list-none flex items-center gap-2">
            <span className="text-muted-foreground">→</span>
            <span className={`font-mono text-xs ${event.tool === 'read_source' ? 'text-indigo-600 dark:text-indigo-400' : ''}`}>{event.tool}</span>
            {event.detail && <span className="text-[10px] text-muted-foreground group-open:hidden">expand</span>}
          </summary>
          {event.detail && (
            <pre className="mt-2 ml-6 bg-muted rounded p-3 text-[11px] font-mono overflow-x-auto leading-relaxed whitespace-pre-wrap break-all">{event.detail}</pre>
          )}
        </details>
      )
    case 'tool_result':
      // Grey-box read_source result renders as first-class chips + source loc.
      if (event.tool === 'read_source' && (event.summary || event.source)) {
        return <GreyBoxResult event={event} />
      }
      return <p className="pl-10 text-xs font-mono text-muted-foreground break-all">{event.detail}</p>
    case 'finding':
      return (
        <div className="reveal pl-4 py-2 flex items-center gap-2 flex-wrap border-l-2 border-red-500/50">
          <span className="text-red-500 text-sm">✓</span>
          <span className="text-sm font-medium">{event.detail}</span>
          {event.source && (
            <span className="inline-flex text-[10px] font-semibold rounded overflow-hidden border border-border">
              <span className="px-1.5 py-0.5 bg-indigo-500/10 text-indigo-600 dark:text-indigo-400">source predicted</span>
              <span className="px-1.5 py-0.5 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400">runtime proved</span>
            </span>
          )}
        </div>
      )
    case 'stopped':
      return <p className="pl-4 py-2 text-xs uppercase tracking-widest text-yellow-600 dark:text-yellow-400">stopped: {event.detail}</p>
    case 'approval_request':
      return <p className="pl-4 py-1.5 text-xs text-red-600 dark:text-red-400 flex items-center gap-2"><span>⏸</span><span className="break-all">awaiting approval — {event.detail}</span></p>
    case 'approval_resolved':
      return (
        <p className={`pl-4 py-1.5 text-xs flex items-center gap-2 ${event.approved ? 'text-emerald-600 dark:text-emerald-400' : 'text-muted-foreground'}`}>
          <span>{event.approved ? '✓' : '✗'}</span><span className="break-all">{event.detail}</span>
        </p>
      )
    default:
      return null
  }
}

function GreyBoxResult({ event }: { event: AgentEvent }) {
  const s = event.summary
  const chips: Array<[string, boolean, boolean]> = s
    // label, active, "active means bad" (red) vs good (green)
    ? [
        ['auth', s.has_auth_check, false],
        ['sanitized', s.sanitizes_input, false],
        ['raw query', s.raw_query, true],
        ['reflects input', s.reflects_input, true],
      ]
    : []
  return (
    <div className="pl-10 py-1.5 space-y-1.5">
      {event.source && (
        <div className="font-mono text-[11px] text-indigo-600 dark:text-indigo-400">
          {event.source.file}:{event.source.line}{event.source.symbol ? ` · ${event.source.symbol}` : ''}
        </div>
      )}
      {chips.length > 0 && (
        <div className="flex flex-wrap gap-1.5">
          {chips.map(([label, active, badWhenActive]) => (
            <span key={label}
              className={`font-mono text-[10px] px-1.5 py-0.5 rounded border ${chipCls(active, badWhenActive)}`}>
              {label} {active ? '✓' : '✗'}
            </span>
          ))}
        </div>
      )}
    </div>
  )
}

// chipCls colors a structural-summary chip: a present guard (auth/sanitized) is
// reassuring (green when on, muted when off); a risky trait (raw query/reflects)
// is alarming (red when on, muted when off).
function chipCls(active: boolean, badWhenActive: boolean): string {
  if (!active) return 'border-border text-muted-foreground'
  return badWhenActive
    ? 'border-red-500/40 bg-red-500/10 text-red-500'
    : 'border-emerald-500/40 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400'
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
  void ticks
  return Math.floor((Date.now() - start) / 1000)
}

function fmtElapsed(s: number): string {
  const m = Math.floor(s / 60)
  const sec = s % 60
  return m > 0 ? `${m}m ${sec}s` : `${sec}s`
}
