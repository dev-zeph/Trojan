import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { SeverityBadge } from './SeverityBadge'
import type { ScanResult, Severity } from '@/types'

const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low', 'info']

interface Props {
  scan: ScanResult
}

export function Dashboard({ scan }: Props) {
  const counts = SEVERITIES.reduce((acc, sev) => {
    acc[sev] = scan.findings.filter(f => f.Severity === sev).length
    return acc
  }, {} as Record<Severity, number>)

  const scanDate = new Date(scan.timestamp).toLocaleString()
  const openCount = scan.findings.filter(f => f.Status === 'open').length

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-2xl font-bold">Scan Results</h2>
        <p className="text-muted-foreground text-sm mt-1">
          {scanDate} · {scan.project_path}
        </p>
      </div>

      <div className="grid grid-cols-2 gap-4 sm:grid-cols-5">
        {SEVERITIES.map(sev => (
          <Card key={sev}>
            <CardHeader className="pb-1 pt-4 px-4">
              <CardTitle className="text-sm font-medium capitalize text-muted-foreground">
                {sev}
              </CardTitle>
            </CardHeader>
            <CardContent className="px-4 pb-4">
              <div className="text-3xl font-bold">{counts[sev]}</div>
            </CardContent>
          </Card>
        ))}
      </div>

      <Card>
        <CardContent className="px-4 py-4 flex gap-6 text-sm">
          <div>
            <span className="text-muted-foreground">Total findings: </span>
            <span className="font-semibold">{scan.findings.length}</span>
          </div>
          <div>
            <span className="text-muted-foreground">Open: </span>
            <span className="font-semibold">{openCount}</span>
          </div>
          <div>
            <span className="text-muted-foreground">Scanners: </span>
            <span className="font-semibold">
              {[...new Set(scan.findings.map(f => f.Scanner))].join(', ') || '—'}
            </span>
          </div>
        </CardContent>
      </Card>

      {/* Severity breakdown preview */}
      <div className="flex flex-wrap gap-2">
        {SEVERITIES.filter(s => counts[s] > 0).map(sev => (
          <div key={sev} className="flex items-center gap-2">
            <SeverityBadge severity={sev} />
            <span className="text-sm">{counts[sev]}</span>
          </div>
        ))}
      </div>
    </div>
  )
}
