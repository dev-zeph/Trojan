import { SeverityDot, SeverityBadge } from './SeverityBadge'
import type { Finding, ScanResult, Severity } from '@/types'

const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low', 'info']
const PREVIEW_COUNT = 5

interface Props {
  scan: ScanResult
  onViewFindings: () => void
  onSelectFinding: (finding: Finding) => void
}

export function Dashboard({ scan, onViewFindings, onSelectFinding }: Props) {
  const counts = SEVERITIES.reduce((acc, sev) => {
    acc[sev] = scan.findings.filter(f => f.Severity === sev).length
    return acc
  }, {} as Record<Severity, number>)

  const scanDate = new Date(scan.timestamp).toLocaleDateString('en-US', {
    year: 'numeric', month: 'long', day: 'numeric',
    hour: '2-digit', minute: '2-digit',
  })

  const scanners = [...new Set(scan.findings.map(f => f.Scanner))]

  // Show the most critical findings first as preview
  const severityOrder: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 }
  const preview = [...scan.findings]
    .sort((a, b) => severityOrder[a.Severity] - severityOrder[b.Severity])
    .slice(0, PREVIEW_COUNT)

  return (
    <div className="space-y-16">

      {/* Hero */}
      <div className="space-y-3">
        <p className="text-xs uppercase tracking-widest text-muted-foreground">{scanDate}</p>
        <h1 className="text-4xl font-bold tracking-tight">
          {scan.findings.length === 0
            ? 'No issues found.'
            : `${scan.findings.length} issue${scan.findings.length === 1 ? '' : 's'} found.`}
        </h1>
        <p className="text-muted-foreground text-sm max-w-lg leading-relaxed">
          Scanned with {scanners.length > 0 ? scanners.join(', ') : '—'}.
          Results are local and have not left your machine.
        </p>
      </div>

      {/* Severity counts */}
      <div className="grid grid-cols-5 gap-0 border-t border-b border-border py-8">
        {SEVERITIES.map((sev, i) => (
          <div
            key={sev}
            className={`px-6 ${i !== 0 ? 'border-l border-border' : ''} space-y-2`}
          >
            <SeverityBadge severity={sev} />
            <p className="text-5xl font-bold tracking-tight">{counts[sev]}</p>
          </div>
        ))}
      </div>

      {/* Meta */}
      <div className="space-y-3 text-sm text-muted-foreground">
        <div className="flex gap-2">
          <span className="text-foreground font-medium w-28">Project</span>
          <span className="font-mono text-xs mt-0.5">{scan.project_path}</span>
        </div>
        <div className="flex gap-2">
          <span className="text-foreground font-medium w-28">Scanners</span>
          <span>{scanners.join(', ') || '—'}</span>
        </div>
        <div className="flex gap-2">
          <span className="text-foreground font-medium w-28">Open</span>
          <span>{scan.findings.filter(f => f.Status === 'open').length} of {scan.findings.length}</span>
        </div>
      </div>

      {/* Findings preview */}
      {preview.length > 0 && (
        <div className="space-y-6">
          <p className="text-xs uppercase tracking-widest text-muted-foreground">Top findings</p>
          <div className="divide-y divide-border">
            {preview.map(finding => (
              <button
                key={finding.ID}
                onClick={() => onSelectFinding(finding)}
                className="w-full text-left py-5 flex items-start gap-4 hover:bg-muted/40 transition-colors px-2 -mx-2 rounded"
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
          </div>

          <button
            onClick={onViewFindings}
            className="text-sm font-medium underline underline-offset-4 hover:text-muted-foreground transition-colors"
          >
            View all {scan.findings.length} findings →
          </button>
        </div>
      )}
    </div>
  )
}
