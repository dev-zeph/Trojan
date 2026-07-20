import { useState } from 'react'
import { SeverityBadge } from './SeverityBadge'
import type { Package, Severity } from '@/types'

interface Props {
  packages: Package[]
}

type Filter = 'all' | 'vulnerable' | 'direct'

const SEV_ORDER: Record<Severity, number> = {
  critical: 0, high: 1, medium: 2, low: 3, info: 4,
}

export function DependencyDashboard({ packages }: Props) {
  const [filter, setFilter] = useState<Filter>('all')
  const [expanded, setExpanded] = useState<string | null>(null)
  const [sortBy, setSortBy] = useState<'severity' | 'name' | 'cves'>('severity')

  if (packages.length === 0) {
    return (
      <div className="space-y-6">
        <p className="text-xs uppercase tracking-widest text-muted-foreground">Dependencies</p>
        <p className="text-muted-foreground text-sm">No dependency data — run a scan on a project with a lock file.</p>
      </div>
    )
  }

  const vulnerable = packages.filter(p => p.cve_count > 0)
  const critical = packages.filter(p => p.highest_severity === 'critical' || p.highest_severity === 'high')

  const filtered = packages.filter(p => {
    if (filter === 'vulnerable') return p.cve_count > 0
    if (filter === 'direct') return p.direct
    return true
  })

  const sorted = [...filtered].sort((a, b) => {
    if (sortBy === 'name') return a.name.localeCompare(b.name)
    if (sortBy === 'cves') return b.cve_count - a.cve_count
    // severity: vulnerable packages first, then by severity rank
    const ra = a.highest_severity ? SEV_ORDER[a.highest_severity] : 99
    const rb = b.highest_severity ? SEV_ORDER[b.highest_severity] : 99
    return ra - rb
  })

  const ecosystems = [...new Set(packages.map(p => p.ecosystem).filter(Boolean))]

  return (
    <div className="space-y-12">

      {/* Header */}
      <div className="space-y-3">
        <p className="text-xs uppercase tracking-widest text-muted-foreground">Dependencies</p>
        <h1 className="text-4xl font-bold tracking-tight">
          {packages.length} package{packages.length !== 1 ? 's' : ''} found.
        </h1>
        <p className="text-muted-foreground text-sm max-w-lg leading-relaxed">
          {vulnerable.length > 0
            ? `${vulnerable.length} with known CVEs · ${critical.length} critical or high severity.`
            : 'No known vulnerabilities detected in your dependencies.'}
          {' '}Ecosystems: {ecosystems.join(', ') || '—'}.
        </p>
      </div>

      {/* Stats row */}
      <div className="grid grid-cols-4 gap-0 border-t border-b border-border py-8">
        {[
          { label: 'Total', value: packages.length },
          { label: 'Vulnerable', value: vulnerable.length },
          { label: 'Direct', value: packages.filter(p => p.direct).length },
          { label: 'Critical / High', value: critical.length },
        ].map((stat, i) => (
          <div key={stat.label} className={`px-6 ${i !== 0 ? 'border-l border-border' : ''} space-y-2`}>
            <p className="text-xs uppercase tracking-widest text-muted-foreground">{stat.label}</p>
            <p className="text-5xl font-bold tracking-tight">{stat.value}</p>
          </div>
        ))}
      </div>

      {/* Controls */}
      <div className="flex items-center justify-between gap-4">
        <div className="flex gap-2">
          {(['all', 'vulnerable', 'direct'] as Filter[]).map(f => (
            <button
              key={f}
              onClick={() => setFilter(f)}
              className={`text-xs px-3 py-1.5 rounded-full border transition-colors capitalize ${
                filter === f
                  ? 'border-foreground bg-foreground text-background'
                  : 'border-border text-muted-foreground hover:border-foreground hover:text-foreground'
              }`}
            >
              {f === 'all' ? `All (${packages.length})` : f === 'vulnerable' ? `Vulnerable (${vulnerable.length})` : `Direct (${packages.filter(p => p.direct).length})`}
            </button>
          ))}
        </div>
        <div className="flex items-center gap-2 text-xs text-muted-foreground">
          <span>Sort:</span>
          {(['severity', 'name', 'cves'] as const).map(s => (
            <button
              key={s}
              onClick={() => setSortBy(s)}
              className={`capitalize transition-colors ${sortBy === s ? 'text-foreground font-medium' : 'hover:text-foreground'}`}
            >
              {s === 'cves' ? 'CVE count' : s}
            </button>
          ))}
        </div>
      </div>

      {/* Package table */}
      <div className="divide-y divide-border">
        {/* Table head */}
        <div className="grid grid-cols-[1fr_auto_auto_auto_auto] gap-4 pb-3 text-xs uppercase tracking-widest text-muted-foreground px-2">
          <span>Package</span>
          <span className="w-20 text-center">Ecosystem</span>
          <span className="w-16 text-center">CVEs</span>
          <span className="w-24 text-center">Severity</span>
          <span className="w-24 text-right">Fix version</span>
        </div>

        {sorted.length === 0 && (
          <p className="py-8 text-sm text-muted-foreground text-center">No packages match this filter.</p>
        )}

        {sorted.map(pkg => {
          const key = `${pkg.name}@${pkg.version}`
          const isExpanded = expanded === key
          const hasAdvisories = (pkg.advisories?.length ?? 0) > 0

          return (
            <div key={key}>
              <button
                onClick={() => hasAdvisories ? setExpanded(isExpanded ? null : key) : undefined}
                className={`w-full grid grid-cols-[1fr_auto_auto_auto_auto] gap-4 items-center py-4 px-2 -mx-2 rounded text-left transition-colors ${
                  hasAdvisories ? 'hover:bg-muted/40 cursor-pointer' : 'cursor-default'
                }`}
              >
                {/* Name + version */}
                <div className="flex items-center gap-3 min-w-0">
                  {hasAdvisories ? (
                    <svg
                      className={`w-3.5 h-3.5 shrink-0 text-muted-foreground transition-transform ${isExpanded ? 'rotate-90' : ''}`}
                      fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}
                    >
                      <path strokeLinecap="round" strokeLinejoin="round" d="M9 5l7 7-7 7" />
                    </svg>
                  ) : (
                    <span className="w-3.5 shrink-0" />
                  )}
                  <div className="min-w-0">
                    <span className="font-medium text-sm font-mono">{pkg.name}</span>
                    <span className="text-xs text-muted-foreground ml-2 font-mono">{pkg.version}</span>
                    {!pkg.direct && (
                      <span className="ml-2 text-xs text-muted-foreground/60">(transitive)</span>
                    )}
                  </div>
                </div>

                {/* Ecosystem */}
                <span className="w-20 text-center text-xs text-muted-foreground font-mono">{pkg.ecosystem}</span>

                {/* CVE count */}
                <span className={`w-16 text-center text-sm font-medium ${pkg.cve_count > 0 ? 'text-foreground' : 'text-muted-foreground/40'}`}>
                  {pkg.cve_count > 0 ? pkg.cve_count : '—'}
                </span>

                {/* Severity badge */}
                <div className="w-24 flex justify-center">
                  {pkg.highest_severity ? (
                    <SeverityBadge severity={pkg.highest_severity} />
                  ) : (
                    <span className="text-xs text-muted-foreground/40">safe</span>
                  )}
                </div>

                {/* Fix version */}
                <span className={`w-24 text-right text-xs font-mono ${pkg.fix_version ? 'text-foreground' : 'text-muted-foreground/40'}`}>
                  {pkg.fix_version ?? (pkg.cve_count > 0 ? 'no fix' : '—')}
                </span>
              </button>

              {/* Expanded advisories */}
              {isExpanded && pkg.advisories && pkg.advisories.length > 0 && (
                <div className="mb-3 ml-10 space-y-2">
                  {pkg.advisories.map(adv => (
                    <div key={adv.id} className="flex items-start gap-3 py-2.5 px-3 rounded bg-muted/30 text-sm">
                      <SeverityBadge severity={adv.severity} />
                      <div className="flex-1 min-w-0 space-y-1">
                        <p className="font-mono text-xs font-medium">{adv.id}</p>
                        {adv.summary && (
                          <p className="text-xs text-muted-foreground leading-snug">{adv.summary}</p>
                        )}
                      </div>
                      {adv.fix_version && (
                        <span className="shrink-0 text-xs font-mono text-muted-foreground">
                          fix: {adv.fix_version}
                        </span>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </div>
          )
        })}
      </div>
    </div>
  )
}
