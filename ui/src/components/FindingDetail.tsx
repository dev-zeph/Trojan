import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { SeverityBadge } from './SeverityBadge'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { resolveFinding, suppressFinding } from '@/api'
import type { Finding } from '@/types'

interface Props {
  finding: Finding
  onBack: () => void
  onAction: () => void
}

export function FindingDetail({ finding, onBack, onAction }: Props) {
  async function handleResolve() {
    await resolveFinding(finding.ID)
    onAction()
  }

  async function handleSuppress() {
    await suppressFinding(finding.ID)
    onAction()
  }

  const vsCodeUrl = `vscode://file/${finding.FilePath}:${finding.LineNumber}`

  return (
    <div className="space-y-4">
      <button
        onClick={onBack}
        className="text-sm text-muted-foreground hover:text-foreground transition-colors"
      >
        ← Back to findings
      </button>

      <div className="flex items-start gap-3">
        <SeverityBadge severity={finding.Severity} />
        <h2 className="text-xl font-bold leading-tight">{finding.Title}</h2>
      </div>

      <div className="flex flex-wrap gap-2">
        <Badge variant="outline">{finding.Scanner}</Badge>
        <Badge variant="outline">{finding.Category}</Badge>
        <Badge variant="outline">{finding.Status}</Badge>
      </div>

      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm text-muted-foreground font-normal">Location</CardTitle>
        </CardHeader>
        <CardContent className="pt-0 flex items-center justify-between">
          <code className="text-sm">
            {finding.FilePath}{finding.LineNumber > 0 ? `:${finding.LineNumber}` : ''}
          </code>
          <a href={vsCodeUrl}>
            <Button variant="outline" size="sm">Open in VS Code</Button>
          </a>
        </CardContent>
      </Card>

      {finding.CodeSnippet && (
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm text-muted-foreground font-normal">Code</CardTitle>
          </CardHeader>
          <CardContent className="pt-0">
            <pre className="bg-muted rounded p-3 text-sm overflow-x-auto">
              <code>{finding.CodeSnippet}</code>
            </pre>
          </CardContent>
        </Card>
      )}

      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm text-muted-foreground font-normal">What this means</CardTitle>
        </CardHeader>
        <CardContent className="pt-0">
          <p className="text-sm leading-relaxed">{finding.RawMessage}</p>
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm text-muted-foreground font-normal">Rule</CardTitle>
        </CardHeader>
        <CardContent className="pt-0">
          <code className="text-xs text-muted-foreground">{finding.RuleID}</code>
        </CardContent>
      </Card>

      <div className="flex gap-2 pt-2">
        <Button onClick={handleResolve} variant="default">Mark resolved</Button>
        <Button onClick={handleSuppress} variant="outline">Suppress rule</Button>
      </div>
    </div>
  )
}
