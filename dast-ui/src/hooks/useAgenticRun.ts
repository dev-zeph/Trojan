import { useEffect, useRef, useState } from 'react'
import { agenticEventsURL, getAgenticStatus } from '@/api'
import type { AgentEvent, GraphEdge, GraphNode, RunStatus } from '@/api'

// GraphState is the folded attack graph — nodes keyed by id, insertion order
// preserved for a stable layout, plus edges (§9.3).
export interface GraphState {
  nodes: Record<string, GraphNode>
  order: string[]
  edges: GraphEdge[]
}

export interface RunState {
  status: RunStatus
  connected: boolean
  events: AgentEvent[]
  steps: number     // highest step number seen
  probes: number    // http_probe tool calls
  findings: number  // note_finding events
  summary: string   // finish summary
  stopReason: string
  errorDetail: string
  graph: GraphState
}

const initial: RunState = {
  status: 'idle',
  connected: false,
  events: [],
  steps: 0,
  probes: 0,
  findings: 0,
  summary: '',
  stopReason: '',
  errorDetail: '',
  graph: { nodes: {}, order: [], edges: [] },
}

// useAgenticRun subscribes to the live run SSE stream and folds events into a
// derived RunState. The stream replays its buffer on connect, so this catches
// up even when mounted mid-run. Terminal state ('complete' | 'error') closes
// the connection.
export function useAgenticRun(enabled: boolean): RunState {
  const [state, setState] = useState<RunState>(initial)
  const esRef = useRef<EventSource | null>(null)

  useEffect(() => {
    if (!enabled) return

    let closed = false
    // Seed status immediately so a run that finished before we connected still
    // renders its terminal banner without waiting on the stream.
    getAgenticStatus().then(s => {
      if (!closed) setState(prev => (prev.status === 'idle' ? { ...prev, status: s.status } : prev))
    })

    const es = new EventSource(agenticEventsURL)
    esRef.current = es

    es.onopen = () => setState(prev => ({ ...prev, connected: true }))
    es.onerror = () => setState(prev => ({ ...prev, connected: false }))

    es.addEventListener('agent', (e: MessageEvent) => {
      let evt: AgentEvent
      try {
        evt = JSON.parse(e.data)
      } catch {
        return
      }
      setState(prev => fold(prev, evt))
      if (evt.type === 'run' && (evt.status === 'complete' || evt.status === 'error')) {
        es.close()
      }
    })

    return () => {
      closed = true
      es.close()
      esRef.current = null
    }
  }, [enabled])

  return state
}

function fold(prev: RunState, evt: AgentEvent): RunState {
  const next: RunState = { ...prev, events: [...prev.events, evt] }
  switch (evt.type) {
    case 'run':
      if (evt.status) next.status = evt.status
      if (evt.status === 'error') next.errorDetail = evt.detail ?? ''
      if (evt.status === 'complete') next.summary = evt.detail ?? next.summary
      break
    case 'step':
      if (evt.step && evt.step > next.steps) next.steps = evt.step
      break
    case 'tool_use':
      if (evt.tool === 'http_probe') next.probes += 1
      break
    case 'finding':
      next.findings += 1
      break
    case 'graph':
      next.graph = foldGraph(prev.graph, evt)
      break
    case 'stopped':
      next.stopReason = evt.detail ?? ''
      break
    case 'finish':
      if (evt.detail) next.summary = evt.detail
      break
  }
  return next
}

// foldGraph applies one graph delta (node upsert or edge add) immutably.
function foldGraph(prev: GraphState, evt: AgentEvent): GraphState {
  if (evt.node) {
    const n = evt.node
    const known = n.id in prev.nodes
    return {
      nodes: { ...prev.nodes, [n.id]: n },
      order: known ? prev.order : [...prev.order, n.id],
      edges: prev.edges,
    }
  }
  if (evt.edge) {
    const e = evt.edge
    const dup = prev.edges.some(x => x.from === e.from && x.to === e.to && x.kind === e.kind)
    return dup ? prev : { ...prev, edges: [...prev.edges, e] }
  }
  return prev
}

// graphCounts derives coverage figures from the folded graph.
export function graphCounts(g: GraphState): { endpoints: number; tested: number; vulnerable: number } {
  let endpoints = 0, tested = 0, vulnerable = 0
  for (const id of g.order) {
    const n = g.nodes[id]
    if (n.type !== 'endpoint') continue
    endpoints++
    if (n.status !== 'untested') tested++
    if (n.status === 'vulnerable' || n.status === 'chained') vulnerable++
  }
  return { endpoints, tested, vulnerable }
}
