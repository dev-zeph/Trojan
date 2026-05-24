import { useState } from 'react'
import { SeverityDot, SeverityBadge } from './SeverityBadge'
import type { Finding, Severity } from '@/types'

const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low', 'info']

interface Props {
  findings: Finding[]
  onSelect: (finding: Finding) => void
}

export function FindingsList({ findings, onSelect }: Props) {
  const [severityFilter, setSeverityFilter] = useState<Severity | 'all'>('all')
  const [scannerFilter, setScannerFilter] = useState<string>('all')

  const scanners = [...new Set(findings.map(f => f.Scanner))]

  const filtered = findings.filter(f => {
    if (severityFilter !== 'all' && f.Severity !== severityFilter) return false
    if (scannerFilter !== 'all' && f.Scanner !== scannerFilter) return false
    return true
  })

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

        <span className="ml-auto text-xs text-muted-foreground">{filtered.length} result{filtered.length !== 1 ? 's' : ''}</span>
      </div>

      {/* List */}
      <div className="divide-y divide-border">
        {filtered.map(finding => (
          <button
            key={finding.ID}
            onClick={() => onSelect(finding)}
            className="w-full text-left py-6 flex items-start gap-4 hover:bg-muted/40 transition-colors px-2 -mx-2 rounded"
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
