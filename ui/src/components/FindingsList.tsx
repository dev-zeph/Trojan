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
  const [scannerFilter, setScannerFilter] = useState<string>('all')

  // Only show open findings — resolved/suppressed are gone from view
  const openFindings = findings.filter(f => f.Status === 'open')

  const scanners = [...new Set(openFindings.map(f => f.Scanner))]

  const applyFilters = (list: Finding[]) =>
    list.filter(f => {
      if (severityFilter !== 'all' && f.Severity !== severityFilter) return false
      if (scannerFilter !== 'all' && f.Scanner !== scannerFilter) return false
      return true
    })

  // No locked partition any more. Scanning runs on the user's machine and
  // costs us nothing, so every finding at every severity is shown to everyone.
  // Cost is metered on the AI layer instead, against the token balance.
  // Sorted most-severe first. Previously only the LOCKED list was sorted, so
  // the findings a free user could actually see came back in scanner order.
  // Now that everything is in one list, critical belongs at the top.
  const visible = applyFilters(openFindings).sort(
    (a, b) => SEVERITY_ORDER[a.Severity] - SEVERITY_ORDER[b.Severity]
  )
  const totalVisible = visible.length

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

        {scanners.length > 1 && (
          <div className="flex items-center gap-3">
            <span className="text-xs uppercase tracking-widest text-muted-foreground">Scanner</span>
            <div className="flex gap-2">
              {scanners.map(s => (
                <FilterPill key={s} active={scannerFilter === s} onClick={() => setScannerFilter(scannerFilter === s ? 'all' : s)}>
                  {s}
                </FilterPill>
              ))}
            </div>
          </div>
        )}

        <span className="ml-auto text-xs text-muted-foreground">{totalVisible} result{totalVisible !== 1 ? 's' : ''}</span>
      </div>

      {/* Accessible findings */}
      <div className="divide-y divide-border">
        {visible.map(finding => (
          <FindingRow key={finding.ID} finding={finding} onClick={() => onSelect(finding)} />
        ))}

        {visible.length === 0 && (
          <p className="py-16 text-center text-sm text-muted-foreground">
            No findings match the current filters.
          </p>
        )}
      </div>

    </div>
  )
}

interface RowProps {
  finding: Finding
  onClick?: () => void
}

function FindingRow({ finding, onClick }: RowProps) {
  return (
    <button
      onClick={onClick}
      className={`w-full text-left py-6 flex items-start gap-4 px-2 -mx-2 rounded transition-colors ${
        'hover:bg-muted/40'
      }`}
    >
      <SeverityDot severity={finding.Severity} />
      <div className="flex-1 min-w-0 space-y-1">
        <p className="font-medium text-sm leading-snug">{finding.Title}</p>
        <p className="text-xs text-muted-foreground font-mono truncate">
          {finding.FilePath}{finding.LineNumber > 0 ? `:${finding.LineNumber}` : ''}
        </p>
      </div>
      <div className="flex items-center gap-4 shrink-0">
        <SeverityBadge severity={finding.Severity} />
        <span className="text-xs text-muted-foreground">{finding.Scanner}</span>
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
