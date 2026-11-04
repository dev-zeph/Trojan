import { useEffect, useRef, useState } from 'react'
import { getIdentities, putIdentities, type Identity } from '@/api'

// TestAccounts — the NON-TECHNICAL surface for authenticated website testing.
//
// Plain-language block where someone types up to two test accounts (just email +
// password). The AI agent logs in as each one to test pages behind a login, and
// compares the two to find cases where one account can see the other's data
// (IDOR). Login URL defaults to the target origin + "/login" and is hidden; no
// advanced fields here (the technical dast-ui/TargetEntry covers those).
//
// Self-contained and importable: give it the website URL being tested, and it
// prefills (masked) from /api/identities on mount and saves back via PUT. It is
// safe to re-save without retyping a password — the backend keeps the stored one.

const TOOLTIP =
  'The AI agent logs in as these two test users and checks whether one account ' +
  'can see the other account’s data — a common, serious bug. Use test ' +
  'accounts you don’t mind it poking at.'

// Mirror the backend's password-like field detection so we know which stored
// field holds the (redacted) secret.
const SECRET_RE = /pass|pwd|secret|token/i

interface SimpleAccount {
  email: string
  password: string
  secretSet: boolean
  // Remembered so a re-save round-trips the exact stored field names.
  emailField: string
  passwordField: string
}

function emptyAccount(): SimpleAccount {
  return { email: '', password: '', secretSet: false, emailField: 'email', passwordField: 'password' }
}

function deriveLoginUrl(target: string): string {
  try {
    return new URL(target).origin + '/login'
  } catch {
    return ''
  }
}

function fromIdentity(id: Identity): SimpleAccount {
  const a = emptyAccount()
  if (id.login) {
    a.secretSet = !!id.login.secret_set
    for (const [k, val] of Object.entries(id.login.fields ?? {})) {
      if (SECRET_RE.test(k)) {
        a.passwordField = k
        a.password = val ?? ''
      } else {
        a.emailField = k
        a.email = val ?? ''
      }
    }
  }
  return a
}

function toIdentities(accounts: SimpleAccount[], defaultLoginUrl: string): Identity[] {
  const out: Identity[] = []
  accounts.forEach((a, i) => {
    const hasContent = a.email.trim() !== '' || a.password !== '' || a.secretSet
    if (!hasContent) return
    out.push({
      name: `account-${i + 1}`,
      login: {
        url: defaultLoginUrl,
        method: 'POST',
        fields: { [a.emailField]: a.email.trim(), [a.passwordField]: a.password },
      },
    })
  })
  return out
}

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
          className="absolute left-1/2 top-6 z-10 w-72 -translate-x-1/2 rounded border border-border bg-background p-2.5 text-xs leading-relaxed text-muted-foreground shadow-md"
        >
          {text}
        </span>
      )}
    </span>
  )
}

interface Props {
  /** The website URL being tested. Identities are stored per target URL. */
  targetUrl: string
  /** Optional: called after a successful save, with the redacted stored view. */
  onSaved?: (identities: Identity[]) => void
}

export function TestAccounts({ targetUrl, onSaved }: Props) {
  const [accounts, setAccounts] = useState<SimpleAccount[]>([emptyAccount(), emptyAccount()])
  const [saving, setSaving] = useState(false)
  const [saved, setSaved] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const loadedUrl = useRef<string>('')

  useEffect(() => {
    const t = targetUrl.trim()
    if (!t || loadedUrl.current === t) return
    loadedUrl.current = t
    getIdentities(t).then(ids => {
      if (ids.length === 0) return
      const next = [emptyAccount(), emptyAccount()]
      ids.slice(0, 2).forEach((id, i) => {
        next[i] = fromIdentity(id)
      })
      setAccounts(next)
    })
  }, [targetUrl])

  function update(i: number, patch: Partial<SimpleAccount>) {
    setAccounts(prev => prev.map((a, idx) => (idx === i ? { ...a, ...patch } : a)))
    setSaved(false)
  }

  async function save() {
    const t = targetUrl.trim()
    if (!t) {
      setError('Enter the website address first.')
      return
    }
    try {
      setSaving(true)
      setError(null)
      const stored = await putIdentities(t, toIdentities(accounts, deriveLoginUrl(t)))
      setSaved(true)
      onSaved?.(stored)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not save test accounts.')
    } finally {
      setSaving(false)
    }
  }

  const inputClass =
    'w-full bg-background border border-border rounded px-3 py-2 text-sm outline-none focus:border-foreground transition-colors'

  return (
    <section className="space-y-4 border border-border rounded-lg p-5">
      <div className="space-y-1">
        <h3 className="text-sm font-medium flex items-center gap-1.5">
          Test accounts
          <span className="text-xs text-muted-foreground">(optional)</span>
          <InfoTip text={TOOLTIP} />
        </h3>
        <p className="text-sm text-muted-foreground leading-relaxed max-w-lg">
          Give the AI two test logins for your site and it will check pages that need you to be
          signed in, including whether one account can peek at the other account&rsquo;s data. Use
          throwaway test accounts, not real ones.
        </p>
      </div>

      <div className="grid gap-4 sm:grid-cols-2">
        {accounts.map((a, i) => (
          <div key={i} className="space-y-3 border border-border rounded p-3">
            <p className="text-xs uppercase tracking-widest text-muted-foreground">
              {i === 0 ? 'First account' : 'Second account'}
            </p>
            <div className="space-y-1.5">
              <label className="text-[10px] uppercase tracking-widest text-muted-foreground">Email</label>
              <input
                type="text"
                autoComplete="off"
                value={a.email}
                onChange={e => update(i, { email: e.target.value })}
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
                onChange={e => update(i, { password: e.target.value })}
                placeholder={a.secretSet ? 'password is set, leave blank to keep' : 'password'}
                className={inputClass}
              />
            </div>
          </div>
        ))}
      </div>

      <div className="flex items-center gap-3">
        <button
          type="button"
          onClick={save}
          disabled={saving}
          className="text-sm font-medium bg-primary text-primary-foreground rounded px-4 py-2 hover:opacity-90 transition-opacity disabled:opacity-50"
        >
          {saving ? 'Saving…' : 'Save test accounts'}
        </button>
        {saved && <span className="text-xs text-muted-foreground">Saved. Stored only on this machine.</span>}
        {error && <span className="text-xs text-destructive">{error}</span>}
      </div>
    </section>
  )
}
