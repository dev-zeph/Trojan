import type { GraphNode } from '@/api'

interface Props {
  node: GraphNode
  onClose: () => void
}

// NodeDetail is the click-through panel for a graph node (compass Area-2:
// click-node → side panel with evidence, attack class, remediation). Its
// signature element is the source↔runtime split (§9.2): the grey-box handler
// beside the live evidence — "source predicted + runtime proved," which no
// black-box tool can render.
export function NodeDetail({ node, onClose }: Props) {
  const proved = node.status === 'vulnerable' || node.status === 'chained'
  return (
    <div className="border border-border rounded bg-background h-full flex flex-col">
      <div className="flex items-start justify-between gap-3 p-4 border-b border-border">
        <div>
          <div className="flex items-center gap-2">
            {node.method && <span className="text-[10px] font-mono font-semibold text-muted-foreground border border-border rounded px-1.5 py-0.5">{node.method}</span>}
            <StatusTag status={node.status} />
          </div>
          <h3 className="text-sm font-mono mt-1.5 break-all">{node.label}</h3>
          {node.attack && <p className="text-xs text-muted-foreground mt-1">{node.attack}{node.severity ? ` · ${node.severity}` : ''}</p>}
        </div>
        <button onClick={onClose} className="text-muted-foreground hover:text-foreground text-lg leading-none" aria-label="Close detail">×</button>
      </div>

      {proved && (node.handler || node.evidence) && (
        <div className="p-4 space-y-3 overflow-y-auto">
          <ProofBadge hasSource={!!node.handler} />
          <div className="grid grid-cols-1 gap-3">
            {node.handler && (
              <div className="rounded border border-indigo-500/30 overflow-hidden">
                <div className="px-3 py-1.5 text-[11px] font-semibold text-indigo-600 dark:text-indigo-400 bg-indigo-500/10 flex items-center justify-between">
                  <span>SOURCE — what the code reveals</span>
                  <span className="font-mono text-[10px] text-muted-foreground">{node.handler.file}:{node.handler.line}</span>
                </div>
                <div className="px-3 py-2 font-mono text-[11px] text-muted-foreground">
                  {node.handler.symbol ? `handler ${node.handler.symbol}()` : 'handler'} — grey-box read
                </div>
              </div>
            )}
            {node.evidence && (
              <div className="rounded border border-emerald-500/30 overflow-hidden">
                <div className="px-3 py-1.5 text-[11px] font-semibold text-emerald-600 dark:text-emerald-400 bg-emerald-500/10">
                  RUNTIME — what the target confirmed
                </div>
                <pre className="px-3 py-2 font-mono text-[11px] whitespace-pre-wrap break-all max-h-48 overflow-y-auto">{node.evidence}</pre>
              </div>
            )}
          </div>
        </div>
      )}

      {!proved && (
        <div className="p-4 text-xs text-muted-foreground">
          {node.status === 'untested' && 'Discovered from the crawl — not yet tested.'}
          {node.status === 'testing' && 'The agent is probing this endpoint now.'}
          {node.status === 'safe' && 'Tested — no issue surfaced.'}
          {node.handler && (
            <div className="mt-3 rounded border border-indigo-500/30 px-3 py-2">
              <span className="text-[11px] font-semibold text-indigo-600 dark:text-indigo-400">Source mapped</span>
              <div className="font-mono text-[10px] text-muted-foreground mt-0.5">{node.handler.file}:{node.handler.line}</div>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

function ProofBadge({ hasSource }: { hasSource: boolean }) {
  if (!hasSource) {
    return <span className="inline-flex text-[11px] font-semibold rounded border border-emerald-500/40 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 px-2 py-0.5">runtime proved</span>
  }
  return (
    <span className="inline-flex text-[11px] font-semibold rounded overflow-hidden border border-border">
      <span className="px-2 py-0.5 bg-indigo-500/10 text-indigo-600 dark:text-indigo-400">source predicted</span>
      <span className="px-2 py-0.5 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400">runtime proved</span>
    </span>
  )
}

function StatusTag({ status }: { status: GraphNode['status'] }) {
  const map: Record<GraphNode['status'], string> = {
    untested: 'text-muted-foreground border-border',
    testing: 'text-yellow-600 dark:text-yellow-400 border-yellow-500/40 bg-yellow-500/10',
    safe: 'text-emerald-600 dark:text-emerald-400 border-emerald-500/40 bg-emerald-500/10',
    vulnerable: 'text-red-500 border-red-500/40 bg-red-500/10',
    chained: 'text-red-400 border-red-400/40 bg-red-400/10',
  }
  return <span className={`text-[10px] font-medium uppercase tracking-widest rounded-full border px-2 py-0.5 ${map[status]}`}>{status}</span>
}
