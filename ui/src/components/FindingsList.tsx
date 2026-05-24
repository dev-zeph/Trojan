import { useState } from 'react'
import { Card, CardContent } from '@/components/ui/card'
import { SeverityBadge } from './SeverityBadge'
import { Badge } from '@/components/ui/badge'
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
    <div className="space-y-4">
      {/* Filters */}
      <div className="flex flex-wrap gap-2">
        <button
          onClick={() => setSeverityFilter('all')}
          className={`text-xs px-3 py-1 rounded-full border transition-colors ${severityFilter === 'all' ? 'bg-foreground text-background' : 'hover:bg-muted'}`}
        >
          All
        </button>
        {SEVERITIES.map(sev => (
          <button
            key={sev}
            onClick={() => setSeverityFilter(sev)}
            className={`text-xs px-3 py-1 rounded-full border transition-colors capitalize ${severityFilter === sev ? 'bg-foreground text-background' : 'hover:bg-muted'}`}
          >
            {sev}
          </button>
        ))}
        <div className="w-px bg-border mx-1" />
        {scanners.map(s => (
          <button
            key={s}
            onClick={() => setScannerFilter(scannerFilter === s ? 'all' : s)}
            className={`text-xs px-3 py-1 rounded-full border transition-colors ${scannerFilter === s ? 'bg-foreground text-background' : 'hover:bg-muted'}`}
          >
            {s}
          </button>
        ))}
      </div>

      <p className="text-sm text-muted-foreground">{filtered.length} finding(s)</p>

      {/* Findings */}
      <div className="space-y-2">
        {filtered.map(finding => (
          <Card
            key={finding.ID}
            className="cursor-pointer hover:bg-muted/50 transition-colors"
            onClick={() => onSelect(finding)}
          >
            <CardContent className="px-4 py-3 flex items-start gap-3">
              <SeverityBadge severity={finding.Severity} />
              <div className="flex-1 min-w-0">
                <p className="font-medium text-sm">{finding.Title}</p>
                <p className="text-xs text-muted-foreground truncate mt-0.5">
                  {finding.FilePath}{finding.LineNumber > 0 ? `:${finding.LineNumber}` : ''}
                </p>
              </div>
              <Badge variant="outline" className="text-xs shrink-0">
                {finding.Scanner}
              </Badge>
            </CardContent>
          </Card>
        ))}

        {filtered.length === 0 && (
          <p className="text-center text-muted-foreground py-12 text-sm">
            No findings match the current filters.
          </p>
        )}
      </div>
    </div>
  )
}
