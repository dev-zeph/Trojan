import { useState } from 'react'
import { SeverityDot, SeverityBadge } from './SeverityBadge'
import type { Finding, Severity } from '@/types'

const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low', 'info']
const SEVERITY_ORDER: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 }

interface Props {
  findings: Finding[]
  onSelect: (finding: Finding) => void
}

export function FindingsList({ findings, onSelect }: Props) {
  const [severityFilter, setSeverityFilter] = useState<Severity | 'all'>('all')

  const openFindings = findings.filter(f => f.Status === 'open')

  const filtered = openFindings
    .filter(f => severityFilter === 'all' || f.Severity === severityFilter)
    .sort((a, b) => SEVERITY_ORDER[a.Severity] - SEVERITY_ORDER[b.Severity])

  return (
    <div className="space-y-10">

      {/* Filters */}
      <div className="flex flex-wrap items-center gap-6 text-sm border-b border-border pb-6">
        <div className="flex items-center gap-3">
          <span className="text-xs uppercase tracking-widest text-muted-foreground">Severity</span>
          <div className="flex gap-2">
            <FilterPill active={severityFilter === 'all'} onClick={() => setSeverityFilter('all')}>All</FilterPill>
            {SEVERITIES.map(sev => (
              <FilterPill key={sev} active={severityFilter === sev} onClick={() => setSeverityFilter(sev)}>
                <span className="capitalize">{sev}</span>
              </FilterPill>
            ))}
          </div>
        </div>
        <span className="ml-auto text-xs text-muted-foreground">
          {filtered.length} result{filtered.length !== 1 ? 's' : ''}
        </span>
      </div>

      {/* Findings */}
      <div className="divide-y divide-border">
        {filtered.map(finding => (
          <FindingRow key={finding.ID} finding={finding} onClick={() => onSelect(finding)} />
        ))}
        {filtered.length === 0 && (
          <p className="py-16 text-center text-sm text-muted-foreground">
            No findings match the current filters.
          </p>
        )}
      </div>
    </div>
  )
}

function FindingRow({ finding, onClick }: { finding: Finding; onClick: () => void }) {
  // Extract just the path from the matched URL for a compact display
  let endpointDisplay = finding.FilePath
  try {
    const u = new URL(finding.FilePath)
    endpointDisplay = u.pathname + u.search
  } catch {
    // not a valid URL — show as-is
  }

  return (
    <button
      onClick={onClick}
      className="w-full text-left py-6 flex items-start gap-4 px-2 -mx-2 rounded transition-colors hover:bg-muted/40"
    >
      <SeverityDot severity={finding.Severity} />
      <div className="flex-1 min-w-0 space-y-1">
        <p className="font-medium text-sm leading-snug">{finding.Title}</p>
        <p className="text-xs text-muted-foreground font-mono truncate">{endpointDisplay}</p>
      </div>
      <div className="flex items-center gap-4 shrink-0">
        <SeverityBadge severity={finding.Severity} />
        <span className="text-xs text-muted-foreground uppercase tracking-wide">{finding.RuleID.split('-')[0]}</span>
      </div>
    </button>
  )
}

function FilterPill({ active, onClick, children }: { active: boolean; onClick: () => void; children: React.ReactNode }) {
  return (
    <button
      onClick={onClick}
      className={`text-xs px-3 py-1 rounded-full border transition-colors ${
        active
          ? 'bg-foreground text-background border-foreground'
          : 'border-border hover:border-foreground/50 text-muted-foreground hover:text-foreground'
      }`}
    >
      {children}
    </button>
  )
}
