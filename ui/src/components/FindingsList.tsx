import { useState } from 'react'
import { SeverityDot, SeverityBadge } from './SeverityBadge'
import type { Finding, Severity } from '@/types'

const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low', 'info']
const SEVERITY_ORDER: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 }

interface Props {
  findings: Finding[]
  lockedCount: number
  onSelect: (finding: Finding) => void
}

export function FindingsList({ findings, lockedCount, onSelect }: Props) {
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

  const unlocked = applyFilters(openFindings.filter(f => !f.locked))
  const locked   = applyFilters(
    [...openFindings.filter(f => f.locked)].sort(
      (a, b) => SEVERITY_ORDER[a.Severity] - SEVERITY_ORDER[b.Severity]
    )
  )

  const totalVisible = unlocked.length + locked.length

  // Only show upgrade banner when the free cap is actually hit
  const unlockedTotal = openFindings.filter(f => !f.locked).length
  const showBanner = lockedCount > 0 && unlockedTotal >= 5

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
        {unlocked.map(finding => (
          <FindingRow key={finding.ID} finding={finding} onClick={() => onSelect(finding)} />
        ))}

        {unlocked.length === 0 && locked.length === 0 && (
          <p className="py-16 text-center text-sm text-muted-foreground">
            No findings match the current filters.
          </p>
        )}
      </div>

      {/* Upgrade banner — sits between accessible and locked findings */}
      {showBanner && locked.length > 0 && (
        <div className="rounded-lg border border-red-500/30 bg-red-500/5 px-6 py-5 flex items-center justify-between gap-6">
          <div className="space-y-1">
            <p className="text-sm font-semibold text-foreground">
              {lockedCount} critical & high severity {lockedCount === 1 ? 'vulnerability' : 'vulnerabilities'} found in this scan
            </p>
            <p className="text-xs text-muted-foreground leading-relaxed">
              Upgrade to Pro to see the full details, AI-powered explanations, and step-by-step fix instructions for every finding.
            </p>
          </div>
          <a
            href="https://trojancli.com/pricing"
            target="_blank"
            rel="noopener noreferrer"
            className="shrink-0 text-xs font-semibold px-4 py-2 rounded bg-foreground text-background hover:opacity-80 transition-opacity whitespace-nowrap"
          >
            Upgrade to Pro →
          </a>
        </div>
      )}

      {/* Locked findings — visible but not accessible */}
      {locked.length > 0 && (
        <div className="divide-y divide-border opacity-40 select-none">
          {locked.map(finding => (
            <FindingRow key={finding.ID} finding={finding} locked />
          ))}
        </div>
      )}

      {/* Edge case: all findings are locked, nothing in the free tier */}
      {unlocked.length === 0 && locked.length > 0 && (
        <div className="py-8 text-center space-y-3">
          <p className="text-sm font-medium text-foreground">No low or medium findings in this scan</p>
          <p className="text-xs text-muted-foreground">
            This scan found {lockedCount} critical & high severity {lockedCount === 1 ? 'vulnerability' : 'vulnerabilities'}.
            Upgrade to Pro to see the full results.
          </p>
          <a
            href="https://trojancli.com/pricing"
            target="_blank"
            rel="noopener noreferrer"
            className="inline-block mt-1 text-xs font-semibold underline underline-offset-4 hover:text-muted-foreground transition-colors"
          >
            Upgrade to Pro →
          </a>
        </div>
      )}
    </div>
  )
}

interface RowProps {
  finding: Finding
  locked?: boolean
  onClick?: () => void
}

function FindingRow({ finding, locked, onClick }: RowProps) {
  return (
    <button
      onClick={locked ? undefined : onClick}
      className={`w-full text-left py-6 flex items-start gap-4 px-2 -mx-2 rounded transition-colors ${
        locked ? 'cursor-default' : 'hover:bg-muted/40'
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
        {locked && (
          <svg className="w-3.5 h-3.5 text-muted-foreground" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M16.5 10.5V6.75a4.5 4.5 0 10-9 0v3.75m-.75 11.25h10.5a2.25 2.25 0 002.25-2.25v-6.75a2.25 2.25 0 00-2.25-2.25H6.75a2.25 2.25 0 00-2.25 2.25v6.75a2.25 2.25 0 002.25 2.25z" />
          </svg>
        )}
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
