import { useMemo } from 'react'
import type { GraphEdge, GraphNode, NodeStatus } from '@/api'
import type { GraphState } from '@/hooks/useAgenticRun'

interface Props {
  graph: GraphState
  selectedId: string | null
  onSelect: (node: GraphNode) => void
}

// Compass Area-2 encoding: untested = gray, testing = amber (live), vulnerable =
// red, chained = red (highlighted), safe = green. Status maps to a Tailwind text
// color; SVG shapes fill/stroke with currentColor.
const statusColor: Record<NodeStatus, string> = {
  untested: 'text-muted-foreground',
  testing: 'text-yellow-500',
  safe: 'text-emerald-600 dark:text-emerald-400',
  vulnerable: 'text-red-500',
  chained: 'text-red-400',
}

const CELL_W = 150
const CELL_H = 96
const PAD = 40

interface Placed {
  node: GraphNode
  x: number
  y: number
}

// AttackGraphView renders the live coverage/vulnerability map (§9.2): endpoints
// laid out on a grid, findings as satellites linked to the endpoint they were
// confirmed on. It's a real-time view — nodes recolor as the agent works. Edges
// stay sparse until the chaining tool (§6.5 #5) lands, at which point the same
// view reads as a kill chain.
export function AttackGraphView({ graph, selectedId, onSelect }: Props) {
  const { placed, width, height, edges } = useMemo(() => layout(graph), [graph])

  if (placed.length === 0) {
    return (
      <div className="h-full min-h-[320px] grid place-items-center text-sm text-muted-foreground">
        Waiting for the crawl map…
      </div>
    )
  }

  const posOf = (id: string) => placed.find(p => p.node.id === id)

  return (
    <div className="overflow-auto rounded border border-border bg-muted/20 h-full">
      <svg
        viewBox={`0 0 ${width} ${height}`}
        width={width}
        height={height}
        className="min-w-full"
        role="img"
        aria-label="Attack coverage graph"
      >
        {/* Edges first so nodes sit on top. Chain edges (the kill chain) get a
            distinct animated broken line; other links stay quiet. */}
        {edges.map((e, i) => {
          const a = posOf(e.from)
          const b = posOf(e.to)
          if (!a || !b) return null
          const s = edgeStyle(e.kind)
          return (
            <line
              key={i}
              x1={a.x} y1={a.y} x2={b.x} y2={b.y}
              className={`${s.cls} ${e.kind === 'chain' ? 'chain-flow' : ''}`}
              stroke="currentColor"
              strokeWidth={s.width}
              strokeDasharray={e.kind === 'chain' ? undefined : s.dash}
            >
              <title>{e.kind}{e.rationale ? `: ${e.rationale}` : ''}</title>
            </line>
          )
        })}

        {placed.map(p => {
          const sel = p.node.id === selectedId
          const isFinding = p.node.type === 'finding'
          const vuln = p.node.status === 'vulnerable' || p.node.status === 'chained'
          const r = isFinding ? 6 : vuln ? 11 : 8
          return (
            <g
              key={p.node.id}
              className={`${statusColor[p.node.status]} cursor-pointer`}
              onClick={() => onSelect(p.node)}
              tabIndex={0}
              role="button"
              aria-label={`${p.node.method ?? ''} ${p.node.label} — ${p.node.status}`}
              onKeyDown={ev => { if (ev.key === 'Enter') onSelect(p.node) }}
            >
              {sel && (
                <circle cx={p.x} cy={p.y} r={r + 5} className="text-foreground" fill="none" stroke="currentColor" strokeWidth={1.5} />
              )}
              {p.node.status === 'testing' && (
                <circle cx={p.x} cy={p.y} r={r + 3} fill="currentColor" opacity={0.25}>
                  <animate attributeName="r" values={`${r + 2};${r + 7};${r + 2}`} dur="1.4s" repeatCount="indefinite" />
                  <animate attributeName="opacity" values="0.3;0;0.3" dur="1.4s" repeatCount="indefinite" />
                </circle>
              )}
              <circle
                cx={p.x} cy={p.y} r={r}
                fill="currentColor"
                fillOpacity={isFinding ? 0.9 : 0.85}
                stroke="currentColor"
                strokeWidth={1}
              />
              {p.node.handler && !isFinding && (
                /* a small square marks endpoints with grey-box source attached */
                <rect x={p.x + r - 1} y={p.y - r - 5} width={6} height={6} className="text-[color:var(--source,#7c7cf0)]" fill="currentColor" />
              )}
              <text
                x={p.x} y={p.y + r + 13}
                textAnchor="middle"
                className="fill-foreground"
                style={{ fontSize: 10, fontFamily: 'ui-monospace, monospace' }}
              >
                {truncate(p.node.label, 16)}
              </text>
            </g>
          )
        })}
      </svg>
    </div>
  )
}

// layout places endpoints on a grid (insertion order) and findings as satellites
// beside the endpoint they link to. Deterministic — no physics, no dependency.
function layout(graph: GraphState): { placed: Placed[]; width: number; height: number; edges: GraphState['edges'] } {
  const endpoints = graph.order.map(id => graph.nodes[id]).filter(n => n.type === 'endpoint')
  // Findings, credentials, and data nodes are all satellites anchored to the
  // node they link to (or gridded below when unlinked).
  const satellites = graph.order.map(id => graph.nodes[id]).filter(n => n.type !== 'endpoint')

  const cols = Math.max(1, Math.ceil(Math.sqrt(endpoints.length || 1)))
  const placed: Placed[] = []
  const pos: Record<string, { x: number; y: number }> = {}

  endpoints.forEach((n, i) => {
    const x = PAD + (i % cols) * CELL_W + CELL_W / 2
    const y = PAD + Math.floor(i / cols) * CELL_H + CELL_H / 2
    pos[n.id] = { x, y }
    placed.push({ node: n, x, y })
  })

  // Place each satellite beside the node it links to (an edge from OR to it),
  // fanning duplicates so they don't stack on the same point.
  const fan: Record<string, number> = {}
  satellites.forEach((n, i) => {
    const link = graph.edges.find(e => e.from === n.id) ?? graph.edges.find(e => e.to === n.id)
    const anchorId = link ? (link.from === n.id ? link.to : link.from) : undefined
    const anchor = anchorId ? pos[anchorId] : undefined
    let x: number, y: number
    if (anchor) {
      const k = anchorId as string
      const nth = (fan[k] = (fan[k] ?? 0) + 1)
      x = anchor.x + 30 + nth * 6
      y = anchor.y - 34 - nth * 4
    } else {
      x = PAD + (i % cols) * CELL_W + CELL_W / 2
      y = PAD + (Math.ceil((endpoints.length || 1) / cols) + Math.floor(i / cols)) * CELL_H + CELL_H / 2
    }
    pos[n.id] = { x, y }
    placed.push({ node: n, x, y })
  })

  const rows = Math.ceil((endpoints.length || 1) / cols) + 1
  const width = Math.max(cols * CELL_W + PAD, 320)
  const height = Math.max(rows * CELL_H + PAD, 320)
  return { placed, width, height, edges: graph.edges }
}

// edgeStyle colors an edge by kind. Chain (kill chain) is the loud one — a red
// animated broken line (dash comes from the .chain-flow CSS class). Dataflow and
// trust stay quiet and dashed; a plain finding link is a faint solid line.
function edgeStyle(kind: GraphEdge['kind']): { cls: string; width: number; dash?: string } {
  switch (kind) {
    case 'chain':
      return { cls: 'text-red-500', width: 2 }
    case 'dataflow':
      return { cls: 'text-indigo-500 dark:text-indigo-400', width: 1.5, dash: '3 3' }
    case 'trust':
      return { cls: 'text-muted-foreground', width: 1.5, dash: '1 4' }
    default:
      return { cls: 'text-border', width: 1.5 }
  }
}

function truncate(s: string, n: number): string {
  return s.length <= n ? s : s.slice(0, n - 1) + '…'
}
