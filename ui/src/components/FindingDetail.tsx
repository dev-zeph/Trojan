import { SeverityBadge } from './SeverityBadge'
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
    <div className="max-w-2xl space-y-12">

      {/* Back */}
      <button
        onClick={onBack}
        className="text-xs uppercase tracking-widest text-muted-foreground hover:text-foreground transition-colors"
      >
        ← Findings
      </button>

      {/* Header */}
      <div className="space-y-4">
        <SeverityBadge severity={finding.Severity} />
        <h1 className="text-3xl font-bold tracking-tight leading-tight">{finding.Title}</h1>
        <div className="flex items-center gap-4 text-xs text-muted-foreground">
          <span>{finding.Scanner}</span>
          <span>·</span>
          <span className="uppercase">{finding.Category}</span>
          <span>·</span>
          <span className="uppercase">{finding.Status}</span>
        </div>
      </div>

      {/* Location */}
      <div className="space-y-2 border-t border-border pt-8">
        <p className="text-xs uppercase tracking-widest text-muted-foreground">Location</p>
        <div className="flex items-center justify-between">
          <code className="text-sm font-mono">
            {finding.FilePath}{finding.LineNumber > 0 ? `:${finding.LineNumber}` : ''}
          </code>
          <a
            href={vsCodeUrl}
            className="text-xs underline underline-offset-4 text-muted-foreground hover:text-foreground transition-colors"
          >
            Open in VS Code
          </a>
        </div>
      </div>

      {/* Code snippet */}
      {finding.CodeSnippet && (
        <div className="space-y-2 border-t border-border pt-8">
          <p className="text-xs uppercase tracking-widest text-muted-foreground">Code</p>
          <pre className="bg-muted rounded p-4 text-xs font-mono overflow-x-auto leading-relaxed">
            {finding.CodeSnippet}
          </pre>
        </div>
      )}

      {/* What this means */}
      <div className="space-y-3 border-t border-border pt-8">
        <p className="text-xs uppercase tracking-widest text-muted-foreground">What this means</p>
        <p className="text-sm leading-relaxed text-foreground/80">{finding.RawMessage}</p>
      </div>

      {/* Simply — AI plain-English explanation */}
      <div className="space-y-4 border-t border-border pt-8">
        <div className="flex items-center justify-between">
          <p className="text-xs uppercase tracking-widest text-muted-foreground">Simply</p>
          {!finding.Simply && (
            <span className="text-xs text-muted-foreground border border-border rounded-full px-2 py-0.5">Pro</span>
          )}
        </div>
        {finding.Simply ? (
          <p className="text-sm leading-relaxed text-foreground/80">{finding.Simply}</p>
        ) : (
          <div className="rounded bg-muted/50 border border-border border-dashed p-6 space-y-2 text-center">
            <p className="text-sm text-muted-foreground leading-relaxed">
              A plain-English explanation of this vulnerability — what it means for your app, why it matters, and a real-world breach with the same root cause.
            </p>
            <a
              href="https://trojancli.com/pricing"
              className="text-xs underline underline-offset-4 text-muted-foreground hover:text-foreground transition-colors"
            >
              Upgrade to Pro →
            </a>
          </div>
        )}
      </div>

      {/* Actions — AI fix suggestions */}
      <div className="space-y-4 border-t border-border pt-8">
        <div className="flex items-center justify-between">
          <p className="text-xs uppercase tracking-widest text-muted-foreground">Actions</p>
          {!finding.Actions?.length && (
            <span className="text-xs text-muted-foreground border border-border rounded-full px-2 py-0.5">Pro</span>
          )}
        </div>
        {finding.Actions?.length ? (
          <ol className="space-y-3">
            {finding.Actions.map((action, i) => (
              <li key={i} className="flex gap-3 text-sm leading-relaxed text-foreground/80">
                <span className="text-xs text-muted-foreground font-mono mt-0.5 shrink-0">{i + 1}.</span>
                <span>{action}</span>
              </li>
            ))}
          </ol>
        ) : (
          <div className="rounded bg-muted/50 border border-border border-dashed p-6 space-y-2 text-center">
            <p className="text-sm text-muted-foreground leading-relaxed">
              Step-by-step actions to fix this vulnerability, with an AI-generated code diff you can apply directly.
            </p>
            <a
              href="https://trojancli.com/pricing"
              className="text-xs underline underline-offset-4 text-muted-foreground hover:text-foreground transition-colors"
            >
              Upgrade to Pro →
            </a>
          </div>
        )}
      </div>

      {/* Rule */}
      <div className="space-y-2 border-t border-border pt-8">
        <p className="text-xs uppercase tracking-widest text-muted-foreground">Rule</p>
        <code className="text-xs font-mono text-muted-foreground">{finding.RuleID}</code>
      </div>

      {/* Resolve / Suppress */}
      <div className="flex gap-6 border-t border-border pt-8">
        <button
          onClick={handleResolve}
          className="text-sm font-medium underline underline-offset-4 hover:text-muted-foreground transition-colors"
        >
          Mark resolved
        </button>
        <button
          onClick={handleSuppress}
          className="text-sm text-muted-foreground underline underline-offset-4 hover:text-foreground transition-colors"
        >
          Suppress rule
        </button>
      </div>
    </div>
  )
}
