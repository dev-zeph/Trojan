import { useState } from 'react'
import { SeverityBadge } from './SeverityBadge'
import { markReal } from '@/api'
import { falseAlarmLabel } from '@/lib/falseAlarms'
import type { Finding } from '@/types'

interface Props {
  hidden: Finding[]
  // Called after the user marks one as real, so the report reloads.
  onChanged: () => void
}

// "Trojan hid N false alarms": a closed-by-default list of the findings the
// AI check judged not real, each with its reason and a way to bring it back.
export function HiddenFalseAlarms({ hidden, onChanged }: Props) {
  const [open, setOpen] = useState(false)
  const [saving, setSaving] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)

  if (hidden.length === 0) return null

  async function handleReal(id: string) {
    setSaving(id)
    setError(null)
    try {
      await markReal(id)
      onChanged()
    } catch {
      setError('Could not save your choice. Try again.')
    } finally {
      setSaving(null)
    }
  }

  return (
    <div className="border-t border-border pt-6 space-y-4">
      <button
        type="button"
        onClick={() => setOpen(o => !o)}
        aria-expanded={open}
        className="text-sm text-muted-foreground underline underline-offset-4 hover:text-foreground transition-colors"
      >
        {falseAlarmLabel(hidden.length)} {open ? '(hide list)' : '(see why)'}
      </button>

      {open && (
        <div className="space-y-2">
          <p className="text-xs text-muted-foreground leading-relaxed max-w-xl">
            Trojan checked these with AI and they look like false alarms, so they don't count against you.
            If one is a real problem, mark it and Trojan will keep showing it on every scan.
          </p>
          {error && <p className="text-xs text-red-600">{error}</p>}
          <ul className="divide-y divide-border">
            {hidden.map(f => (
              <li key={f.ID} className="py-4 flex items-start gap-4" data-testid="hidden-false-alarm">
                <div className="flex-1 min-w-0 space-y-1">
                  <p className="font-medium text-sm leading-snug">{f.Title}</p>
                  <p className="text-xs text-muted-foreground font-mono truncate">
                    {f.FilePath}{f.LineNumber > 0 ? `:${f.LineNumber}` : ''}
                  </p>
                  {f.VerdictReason && (
                    <p className="text-xs text-foreground/80 leading-relaxed">
                      <span className="text-muted-foreground">Why: </span>{f.VerdictReason}
                    </p>
                  )}
                </div>
                <div className="flex items-center gap-4 shrink-0">
                  <SeverityBadge severity={f.Severity} />
                  <button
                    type="button"
                    onClick={() => handleReal(f.ID)}
                    disabled={saving === f.ID}
                    className="text-xs font-medium underline underline-offset-4 hover:text-muted-foreground transition-colors disabled:opacity-50"
                  >
                    {saving === f.ID ? 'Saving…' : 'This is a real issue'}
                  </button>
                </div>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  )
}
