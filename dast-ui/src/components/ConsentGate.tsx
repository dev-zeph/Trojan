import { useEffect, useState } from 'react'
import { mintConsent, verifyConsent } from '@/api'
import type { MintResult, VerifyMethod } from '@/api'

interface Props {
  url: string
  onVerified: (domain: string) => void
}

const METHODS: { key: VerifyMethod; label: string }[] = [
  { key: 'dns', label: 'DNS TXT' },
  { key: 'file', label: 'Well-known file' },
  { key: 'meta', label: 'Meta tag' },
]

// ConsentGate (§10.2 screen 2, gate from §4) — proves domain ownership before a
// scan of a non-local target is allowed. Mints a token, shows the three
// placement options, and checks the one the user chose. Used by the desktop
// pre-run flow; wired to /api/dast/consent/*.
export function ConsentGate({ url, onVerified }: Props) {
  const [mint, setMint] = useState<MintResult | null>(null)
  const [method, setMethod] = useState<VerifyMethod>('dns')
  const [checking, setChecking] = useState(false)
  const [failure, setFailure] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    setMint(null)
    setError(null)
    mintConsent(url)
      .then(m => {
        setMint(m)
        if (m.isLocal) onVerified(m.domain)
      })
      .catch(e => setError(e instanceof Error ? e.message : 'Could not prepare verification.'))
  }, [url, onVerified])

  async function check() {
    if (!mint) return
    setChecking(true)
    setFailure(null)
    try {
      const res = await verifyConsent(url, method)
      if (res.verified) {
        onVerified(res.domain ?? mint.domain)
      } else {
        setFailure(res.error ?? 'Token not found yet. Give DNS/CDN a moment and try again.')
      }
    } finally {
      setChecking(false)
    }
  }

  if (error) {
    return <p className="text-sm text-red-500">{error}</p>
  }
  if (!mint) {
    return <p className="text-sm text-muted-foreground">Preparing verification…</p>
  }
  if (mint.isLocal) {
    return (
      <p className="text-sm text-muted-foreground">
        <span className="font-mono text-foreground">{mint.domain}</span> is a local target — no ownership check needed.
      </p>
    )
  }

  return (
    <div className="max-w-2xl space-y-8">
      <div className="space-y-2">
        <h2 className="text-xl font-bold tracking-tight">Prove you own {mint.domain}</h2>
        <p className="text-sm text-muted-foreground leading-relaxed">
          Pen-testing a domain you don't control is illegal. Place the token below using any one method, then verify — the same model as Google Search Console.
        </p>
      </div>

      {/* Token */}
      <div className="space-y-2">
        <p className="text-[10px] uppercase tracking-widest text-muted-foreground">Verification token</p>
        <code className="block bg-muted rounded p-3 text-xs font-mono break-all select-all">{mint.token}</code>
      </div>

      {/* Method tabs */}
      <div className="space-y-4">
        <div className="flex gap-1 border-b border-border">
          {METHODS.map(m => (
            <button
              key={m.key}
              onClick={() => { setMethod(m.key); setFailure(null) }}
              className={`text-xs font-medium px-3 py-2 -mb-px border-b-2 transition-colors ${
                method === m.key
                  ? 'border-foreground text-foreground'
                  : 'border-transparent text-muted-foreground hover:text-foreground'
              }`}
            >
              {m.label}
            </button>
          ))}
        </div>
        <MethodInstructions method={method} mint={mint} />
      </div>

      {/* Check */}
      <div className="flex items-center gap-4">
        <button
          onClick={check}
          disabled={checking}
          className="text-sm font-medium bg-primary text-primary-foreground rounded px-4 py-2 hover:opacity-90 transition-opacity disabled:opacity-50"
        >
          {checking ? 'Checking…' : 'Check now'}
        </button>
        {failure && <p className="text-xs text-yellow-600 dark:text-yellow-400">{failure}</p>}
      </div>
    </div>
  )
}

function MethodInstructions({ method, mint }: { method: VerifyMethod; mint: MintResult }) {
  if (method === 'dns') {
    return (
      <Instruction text={`Add a DNS TXT record on ${mint.domain} with value:`}>
        {mint.txtPrefix}{mint.token}
      </Instruction>
    )
  }
  if (method === 'file') {
    return (
      <Instruction text="Serve this file with the token as its body:">
        {mint.wellKnownPath}
      </Instruction>
    )
  }
  return (
    <Instruction text="Add this tag to the <head> of your homepage:">
      {`<meta name="${mint.metaName}" content="${mint.token}">`}
    </Instruction>
  )
}

function Instruction({ text, children }: { text: string; children: React.ReactNode }) {
  return (
    <div className="space-y-2">
      <p className="text-sm text-foreground/80">{text}</p>
      <code className="block bg-muted rounded p-3 text-xs font-mono break-all select-all">{children}</code>
    </div>
  )
}
