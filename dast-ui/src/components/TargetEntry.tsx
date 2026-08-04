import { useState } from 'react'

export type Tier = 'passive' | 'safe-active' | 'aggressive'
export type Environment = 'production' | 'staging'

export interface RunConfig {
  url: string
  tier: Tier
  environment: Environment
  acceptSideEffects: boolean
}

interface Props {
  defaultUrl?: string
  onStart: (cfg: RunConfig) => void
}

const TIERS: { key: Tier; label: string; desc: string }[] = [
  { key: 'passive', label: 'Passive', desc: 'GET/HEAD only — safe anywhere, including production.' },
  { key: 'safe-active', label: 'Safe-active', desc: 'Adds non-destructive POST confirmation (injection / reflected-XSS).' },
  { key: 'aggressive', label: 'Aggressive', desc: 'Stored-XSS + state-touching probes. Staging only.' },
]

// TargetEntry (§10.2 screen 1) — where a run is configured: URL, environment,
// and scan-intensity tier. Emits a RunConfig; the host (desktop tab) starts the
// run. Enforces the §6.2 gates in the UI (aggressive ⇒ staging; safe-active POST
// on production ⇒ explicit side-effect ack) so the choice is legible before the
// client re-enforces them.
export function TargetEntry({ defaultUrl, onStart }: Props) {
  const [url, setUrl] = useState(defaultUrl ?? '')
  const [tier, setTier] = useState<Tier>('passive')
  const [environment, setEnvironment] = useState<Environment>('production')
  const [ack, setAck] = useState(false)

  const aggressiveOnProd = tier === 'aggressive' && environment === 'production'
  const needsAck = tier === 'safe-active' && environment === 'production'
  const canStart = url.trim() !== '' && !aggressiveOnProd && (!needsAck || ack)

  return (
    <form
      className="max-w-2xl space-y-8"
      onSubmit={e => {
        e.preventDefault()
        if (canStart) onStart({ url: url.trim(), tier, environment, acceptSideEffects: ack })
      }}
    >
      <div className="space-y-2">
        <h2 className="text-xl font-bold tracking-tight">New penetration test</h2>
        <p className="text-sm text-muted-foreground leading-relaxed">
          Only scan servers you own or are explicitly authorized to test. Unauthorized scanning is illegal.
        </p>
      </div>

      {/* URL */}
      <div className="space-y-2">
        <label className="text-[10px] uppercase tracking-widest text-muted-foreground">Target URL</label>
        <input
          type="url"
          value={url}
          onChange={e => setUrl(e.target.value)}
          placeholder="https://staging.example.com"
          className="w-full bg-background border border-border rounded px-3 py-2 text-sm font-mono outline-none focus:border-foreground transition-colors"
          autoFocus
        />
      </div>

      {/* Environment */}
      <div className="space-y-2">
        <span className="text-[10px] uppercase tracking-widest text-muted-foreground">Environment</span>
        <div className="flex gap-2">
          {(['production', 'staging'] as Environment[]).map(env => (
            <button
              key={env}
              type="button"
              onClick={() => setEnvironment(env)}
              className={`text-sm px-3 py-1.5 rounded border capitalize transition-colors ${
                environment === env ? 'border-foreground bg-muted' : 'border-border text-muted-foreground hover:text-foreground'
              }`}
            >
              {env}
            </button>
          ))}
        </div>
      </div>

      {/* Tier */}
      <div className="space-y-2">
        <span className="text-[10px] uppercase tracking-widest text-muted-foreground">Scan intensity</span>
        <div className="space-y-1.5">
          {TIERS.map(t => {
            const disabled = t.key === 'aggressive' && environment === 'production'
            return (
              <button
                key={t.key}
                type="button"
                disabled={disabled}
                onClick={() => setTier(t.key)}
                className={`w-full text-left px-3 py-2.5 rounded border transition-colors ${
                  tier === t.key ? 'border-foreground bg-muted' : 'border-border hover:border-foreground/50'
                } ${disabled ? 'opacity-40 cursor-not-allowed' : ''}`}
              >
                <div className="text-sm font-medium">{t.label}</div>
                <div className="text-xs text-muted-foreground mt-0.5">
                  {t.desc}
                  {disabled && ' (switch to staging to enable)'}
                </div>
              </button>
            )
          })}
        </div>
      </div>

      {/* Side-effect ack */}
      {needsAck && (
        <label className="flex items-start gap-2 text-sm text-foreground/80 cursor-pointer">
          <input type="checkbox" checked={ack} onChange={e => setAck(e.target.checked)} className="mt-1" />
          <span>I understand safe-active POST probes against production may cause side effects, and I accept them.</span>
        </label>
      )}

      <button
        type="submit"
        disabled={!canStart}
        className="text-sm font-medium bg-primary text-primary-foreground rounded px-4 py-2 hover:opacity-90 transition-opacity disabled:opacity-50"
      >
        Continue
      </button>
    </form>
  )
}
