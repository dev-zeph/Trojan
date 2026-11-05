import { useEffect, useRef, useState, type FormEvent } from 'react'
import { getIdentities, putIdentities, type Identity } from '../api'

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

const AUTH_TOOLTIP =
  'Trojan logs in as these test accounts to test pages that require a login. ' +
  'Two accounts let it check whether one account can reach another’s data (IDOR). ' +
  'Use throwaway test accounts only.'

// Password-like field keys are redacted by the backend on read and preserved on
// save when sent empty. Mirror the backend's detection so the UI knows which
// field holds the secret.
const SECRET_RE = /pass|pwd|secret|token/i

// Local editing shape for one test account. Maps to/from the wire `Identity`.
interface AuthAccount {
  label: string
  loginUrl: string
  email: string
  password: string
  emailField: string
  passwordField: string
  secretSet: boolean
  showFieldNames: boolean
  mode: 'login' | 'header'
  headerType: 'Cookie' | 'Authorization'
  headerValue: string
}

function emptyAccount(): AuthAccount {
  return {
    label: '',
    loginUrl: '',
    email: '',
    password: '',
    emailField: 'email',
    passwordField: 'password',
    secretSet: false,
    showFieldNames: false,
    mode: 'login',
    headerType: 'Cookie',
    headerValue: '',
  }
}

function deriveLoginUrl(target: string): string {
  try {
    return new URL(target).origin + '/login'
  } catch {
    return ''
  }
}

// Map a stored identity (redacted) into the editing shape.
function fromIdentity(id: Identity): AuthAccount {
  const a = emptyAccount()
  a.label = /^account-\d+$/.test(id.name ?? '') ? '' : (id.name ?? '')
  if (id.headers && Object.keys(id.headers).length > 0) {
    a.mode = 'header'
    const [h, v] = Object.entries(id.headers)[0]
    a.headerType = /^authorization$/i.test(h) ? 'Authorization' : 'Cookie'
    a.headerValue = v ?? ''
  } else if (id.login) {
    a.loginUrl = id.login.url ?? ''
    a.secretSet = !!id.login.secret_set
    for (const [k, val] of Object.entries(id.login.fields ?? {})) {
      if (SECRET_RE.test(k)) {
        a.passwordField = k
        a.password = val ?? '' // redacted "" on read
      } else {
        a.emailField = k
        a.email = val ?? ''
      }
    }
    // Reveal the field-name editor when they differ from the defaults.
    a.showFieldNames = a.emailField !== 'email' || a.passwordField !== 'password'
  }
  return a
}

// Build the wire identities from the editing shape. Empty accounts are dropped.
// A password sent empty on a secret_set account is preserved by the backend.
function toIdentities(accounts: AuthAccount[], defaultLoginUrl: string): Identity[] {
  const out: Identity[] = []
  accounts.forEach((a, i) => {
    const name = a.label.trim() || `account-${i + 1}`
    if (a.mode === 'header') {
      if (!a.headerValue.trim()) return
      out.push({ name, headers: { [a.headerType]: a.headerValue.trim() } })
      return
    }
    const hasContent = a.email.trim() !== '' || a.password !== '' || a.secretSet
    if (!hasContent) return
    const emailField = a.emailField.trim() || 'email'
    const passwordField = a.passwordField.trim() || 'password'
    out.push({
      name,
      login: {
        url: a.loginUrl.trim() || defaultLoginUrl,
        method: 'POST',
        fields: { [emailField]: a.email.trim(), [passwordField]: a.password },
      },
    })
  })
  return out
}

// A small (?) info tooltip, shown on hover/focus. Kept inline so TargetEntry has
// no new component dependencies.
function InfoTip({ text }: { text: string }) {
  const [show, setShow] = useState(false)
  return (
    <span className="relative inline-flex align-middle">
      <button
        type="button"
        title={text}
        aria-label={text}
        onMouseEnter={() => setShow(true)}
        onMouseLeave={() => setShow(false)}
        onFocus={() => setShow(true)}
        onBlur={() => setShow(false)}
        className="inline-flex h-4 w-4 items-center justify-center rounded-full border border-border text-[10px] leading-none text-muted-foreground hover:text-foreground hover:border-foreground transition-colors"
      >
        ?
      </button>
      {show && (
        <span
          role="tooltip"
          className="absolute left-1/2 top-6 z-10 w-72 -translate-x-1/2 rounded border border-border bg-background p-2.5 text-xs font-normal normal-case leading-relaxed tracking-normal text-muted-foreground shadow-md"
        >
          {text}
        </span>
      )}
    </span>
  )
}

// TargetEntry (§10.2 screen 1) — where a run is configured: URL, environment,
// and scan-intensity tier. Emits a RunConfig; the host (desktop tab) starts the
// run. Enforces the §6.2 gates in the UI (aggressive ⇒ staging; safe-active POST
// on production ⇒ explicit side-effect ack) so the choice is legible before the
// client re-enforces them.
//
// Also captures optional authenticated-testing identities (test accounts) so the
// agent can log in behind a wall and compare two accounts for IDOR. Credentials
// are prefilled masked from /api/identities on mount and saved back on start.
export function TargetEntry({ defaultUrl, onStart }: Props) {
  const [url, setUrl] = useState(defaultUrl ?? '')
  const [tier, setTier] = useState<Tier>('passive')
  const [environment, setEnvironment] = useState<Environment>('production')
  const [ack, setAck] = useState(false)

  const [authOpen, setAuthOpen] = useState(false)
  const [accounts, setAccounts] = useState<AuthAccount[]>([])
  const [authError, setAuthError] = useState<string | null>(null)
  const [saving, setSaving] = useState(false)
  const loadedUrl = useRef<string>('')

  const aggressiveOnProd = tier === 'aggressive' && environment === 'production'
  const needsAck = tier === 'safe-active' && environment === 'production'
  const canStart = url.trim() !== '' && !aggressiveOnProd && (!needsAck || ack) && !saving

  const defaultLoginUrl = deriveLoginUrl(url)

  // Prefill (masked) from storage. Keyed by target URL so a distinct target is
  // loaded once; re-typing the same URL does not clobber in-progress edits.
  async function loadIdentities(target: string) {
    const t = target.trim()
    if (!t || loadedUrl.current === t) return
    loadedUrl.current = t
    const ids = await getIdentities(t)
    if (ids.length > 0) setAccounts(ids.slice(0, 2).map(fromIdentity))
  }

  useEffect(() => {
    const t = (defaultUrl ?? '').trim()
    if (t) void loadIdentities(t)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  function toggleAuth() {
    const next = !authOpen
    setAuthOpen(next)
    if (next) {
      void loadIdentities(url)
      if (accounts.length === 0) setAccounts([emptyAccount()])
    }
  }

  function updateAccount(i: number, patch: Partial<AuthAccount>) {
    setAccounts(prev => prev.map((a, idx) => (idx === i ? { ...a, ...patch } : a)))
  }
  function addAccount() {
    setAccounts(prev => (prev.length >= 2 ? prev : [...prev, emptyAccount()]))
  }
  function removeAccount(i: number) {
    setAccounts(prev => prev.filter((_, idx) => idx !== i))
  }

  async function handleSubmit(e: FormEvent) {
    e.preventDefault()
    if (!canStart) return
    const target = url.trim()
    try {
      setSaving(true)
      setAuthError(null)
      // Persist test accounts if the user has engaged the section, so edits
      // (including clearing an account) are saved before the run starts.
      if (authOpen || accounts.length > 0) {
        await putIdentities(target, toIdentities(accounts, deriveLoginUrl(target)))
      }
      onStart({ url: target, tier, environment, acceptSideEffects: ack })
    } catch (err) {
      setAuthError(err instanceof Error ? err.message : 'Could not save test accounts.')
    } finally {
      setSaving(false)
    }
  }

  const inputClass =
    'w-full bg-background border border-border rounded px-3 py-2 text-sm outline-none focus:border-foreground transition-colors'

  return (
    <form className="max-w-2xl space-y-8" onSubmit={handleSubmit}>
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
          className={`${inputClass} font-mono`}
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

      {/* Authenticated testing (optional) */}
      <div className="space-y-3 border border-border rounded">
        <button
          type="button"
          onClick={toggleAuth}
          className="w-full flex items-center justify-between px-3 py-2.5 text-left"
          aria-expanded={authOpen}
        >
          <span className="flex items-center gap-1.5">
            <span className="text-sm font-medium">Authenticated testing</span>
            <span className="text-xs text-muted-foreground">(optional)</span>
            <InfoTip text={AUTH_TOOLTIP} />
          </span>
          <span className="text-muted-foreground text-xs">{authOpen ? '−' : '+'}</span>
        </button>

        {authOpen && (
          <div className="px-3 pb-3 space-y-4">
            <p className="text-xs text-muted-foreground leading-relaxed">
              Add up to two test accounts. Trojan logs in as each one to test pages behind a login; with two it
              checks whether one account can reach the other&rsquo;s data. Use throwaway test accounts only.
            </p>

            {accounts.map((a, i) => (
              <div key={i} className="space-y-3 border border-border rounded p-3">
                <div className="flex items-center justify-between">
                  <input
                    value={a.label}
                    onChange={e => updateAccount(i, { label: e.target.value })}
                    placeholder={`account-${i + 1}`}
                    className="bg-transparent text-sm font-medium outline-none border-b border-transparent focus:border-border transition-colors w-40"
                    aria-label={`Account ${i + 1} label`}
                  />
                  <button
                    type="button"
                    onClick={() => removeAccount(i)}
                    className="text-xs text-muted-foreground hover:text-foreground transition-colors"
                  >
                    Remove
                  </button>
                </div>

                {a.mode === 'login' ? (
                  <>
                    <div className="space-y-1.5">
                      <label className="text-[10px] uppercase tracking-widest text-muted-foreground">Login URL</label>
                      <input
                        type="url"
                        value={a.loginUrl}
                        onChange={e => updateAccount(i, { loginUrl: e.target.value })}
                        placeholder={defaultLoginUrl || 'https://example.com/login'}
                        className={`${inputClass} font-mono`}
                      />
                    </div>
                    <div className="space-y-1.5">
                      <label className="text-[10px] uppercase tracking-widest text-muted-foreground">Email</label>
                      <input
                        type="text"
                        autoComplete="off"
                        value={a.email}
                        onChange={e => updateAccount(i, { email: e.target.value })}
                        placeholder="test-user@example.com"
                        className={inputClass}
                      />
                    </div>
                    <div className="space-y-1.5">
                      <label className="text-[10px] uppercase tracking-widest text-muted-foreground">Password</label>
                      <input
                        type="password"
                        autoComplete="new-password"
                        value={a.password}
                        onChange={e => updateAccount(i, { password: e.target.value })}
                        placeholder={a.secretSet ? 'password is set, leave blank to keep' : 'password'}
                        className={inputClass}
                      />
                    </div>

                    <button
                      type="button"
                      onClick={() => updateAccount(i, { showFieldNames: !a.showFieldNames })}
                      className="text-xs text-muted-foreground hover:text-foreground transition-colors"
                    >
                      {a.showFieldNames ? '− Field names' : '+ Advanced: field names'}
                    </button>
                    {a.showFieldNames && (
                      <div className="grid grid-cols-2 gap-2">
                        <div className="space-y-1.5">
                          <label className="text-[10px] uppercase tracking-widest text-muted-foreground">Email field</label>
                          <input
                            value={a.emailField}
                            onChange={e => updateAccount(i, { emailField: e.target.value })}
                            placeholder="email"
                            className={`${inputClass} font-mono`}
                          />
                        </div>
                        <div className="space-y-1.5">
                          <label className="text-[10px] uppercase tracking-widest text-muted-foreground">Password field</label>
                          <input
                            value={a.passwordField}
                            onChange={e => updateAccount(i, { passwordField: e.target.value })}
                            placeholder="password"
                            className={`${inputClass} font-mono`}
                          />
                        </div>
                      </div>
                    )}

                    <button
                      type="button"
                      onClick={() => updateAccount(i, { mode: 'header' })}
                      className="block text-xs text-muted-foreground hover:text-foreground transition-colors"
                    >
                      Advanced: paste a session cookie / header instead
                    </button>
                  </>
                ) : (
                  <>
                    <div className="space-y-1.5">
                      <label className="text-[10px] uppercase tracking-widest text-muted-foreground">Header</label>
                      <div className="flex gap-2">
                        {(['Cookie', 'Authorization'] as const).map(h => (
                          <button
                            key={h}
                            type="button"
                            onClick={() => updateAccount(i, { headerType: h })}
                            className={`text-sm px-3 py-1.5 rounded border transition-colors ${
                              a.headerType === h ? 'border-foreground bg-muted' : 'border-border text-muted-foreground hover:text-foreground'
                            }`}
                          >
                            {h}
                          </button>
                        ))}
                      </div>
                    </div>
                    <div className="space-y-1.5">
                      <label className="text-[10px] uppercase tracking-widest text-muted-foreground">Value</label>
                      <textarea
                        value={a.headerValue}
                        onChange={e => updateAccount(i, { headerValue: e.target.value })}
                        placeholder={a.headerType === 'Cookie' ? 'session=abc123; ...' : 'Bearer eyJ...'}
                        rows={2}
                        className={`${inputClass} font-mono resize-none`}
                      />
                    </div>
                    <button
                      type="button"
                      onClick={() => updateAccount(i, { mode: 'login' })}
                      className="block text-xs text-muted-foreground hover:text-foreground transition-colors"
                    >
                      Use email + password instead
                    </button>
                  </>
                )}
              </div>
            ))}

            {accounts.length < 2 && (
              <button
                type="button"
                onClick={addAccount}
                className="text-sm px-3 py-1.5 rounded border border-border text-muted-foreground hover:text-foreground hover:border-foreground/50 transition-colors"
              >
                {accounts.length === 0 ? 'Add a test account' : 'Add a second account'}
              </button>
            )}

            {authError && <p className="text-xs text-destructive">{authError}</p>}
          </div>
        )}
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
        {saving ? 'Saving…' : 'Continue'}
      </button>
    </form>
  )
}
