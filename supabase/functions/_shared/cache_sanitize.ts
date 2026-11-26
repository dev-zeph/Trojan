// Defensive checks for anything written to a cache that is SHARED ACROSS USERS
// (ai_cache today). The shared row must be generic: no file paths, code, secrets,
// URLs of the user's site, profile text or anything else that came from one
// user's request. The prompt that feeds a shared row is already built from
// generic inputs only; these checks are the second line of defence, so they err
// on the side of "don't cache". A rejected row is still returned to the caller
// that paid for it; it is just never stored or served to anyone else.

export interface SharedCacheCheck {
  ok: boolean
  /** Machine-readable reasons, safe to log: they never contain the matched text. */
  reasons: string[]
}

// Hosts a generic explanation may legitimately link to (standards, advisories,
// vendor docs). Any other URL in shared output is treated as user-specific.
const DOC_HOSTS = [
  'owasp.org', 'cheatsheetseries.owasp.org', 'cwe.mitre.org', 'cve.mitre.org', 'cve.org',
  'nvd.nist.gov', 'developer.mozilla.org', 'semgrep.dev', 'docs.github.com',
  'github.com', 'osv.dev', 'snyk.io', 'portswigger.net', 'datatracker.ietf.org',
  'nodejs.org', 'docs.python.org', 'go.dev', 'pkg.go.dev', 'php.net', 'www.php.net',
  'learn.microsoft.com', 'cloud.google.com', 'docs.aws.amazon.com', 'stripe.com',
  'docs.stripe.com', 'supabase.com', 'nextjs.org', 'expressjs.com', 'example.com',
]

const SECRET_PATTERNS: Array<[string, RegExp]> = [
  ['aws_key', /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/],
  ['github_token', /\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b/],
  ['stripe_key', /\b(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{8,}\b/],
  ['slack_token', /\bxox[abposr]-[A-Za-z0-9-]{10,}\b/],
  ['google_key', /\bAIza[0-9A-Za-z_-]{30,}\b/],
  ['private_key', /-----BEGIN [A-Z ]*PRIVATE KEY-----/],
  ['jwt', /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}\b/],
  ['anthropic_or_openai_key', /\bsk-(?:ant-)?[A-Za-z0-9_-]{20,}\b/],
  ['db_url_with_password', /\b[a-z][a-z0-9+.-]*:\/\/[^\s:@/]+:[^\s@/]+@/i],
]

const ABS_PATH = /(?:^|[\s"'`(=])(?:\/(?:Users|home|root|var|private|tmp|opt|srv|mnt|etc\/[\w.-]+\/)[^\s"'`)]*|[A-Za-z]:\\[^\s"'`)]+|~\/[^\s"'`)]+)/
// A relative path with at least one directory and a file extension: src/a/b.ts
const REL_PATH = /\b(?:[\w@.-]+\/)+[\w.-]+\.[A-Za-z0-9]{1,8}\b/
const URL_RE = /\bhttps?:\/\/([^\s/"'`)<>]+)[^\s"'`)<>]*/gi
const EMAIL = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/
const IPV4 = /\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b/g
const ALLOWED_IPS = new Set(['127.0.0.1', '0.0.0.0', '169.254.169.254', '255.255.255.255'])
const CODE_FENCE = /```|~~~/
const LONG_INLINE_CODE = /`[^`\n]{61,}`/
// A line that reads like source code rather than prose (statements, braces, assignments).
// Case-sensitive on purpose: prose sentences start with a capital ("Return a 404 ...").
const CODE_LINE = /(?:;\s*$|^\s*(?:const|let|var|function|def|import|return|SELECT|INSERT|UPDATE|DELETE)\s.*[=({;]|^\s*if\s*\(.*\)\s*\{|\{\s*$|=>\s*\{)/m

function shannonEntropy(s: string): number {
  const freq = new Map<string, number>()
  for (const ch of s) freq.set(ch, (freq.get(ch) ?? 0) + 1)
  let h = 0
  for (const n of freq.values()) {
    const p = n / s.length
    h -= p * Math.log2(p)
  }
  return h
}

/** A long, random-looking token (an API key nobody has a pattern for). */
function hasHighEntropyToken(text: string): boolean {
  for (const m of text.matchAll(/[A-Za-z0-9+/_=-]{32,}/g)) {
    const t = m[0]
    const classes = [/[a-z]/, /[A-Z]/, /[0-9]/].filter((r) => r.test(t)).length
    if (classes >= 2 && shannonEntropy(t) >= 4.0) return true
  }
  return false
}

function isDocHost(host: string): boolean {
  const h = host.toLowerCase().replace(/:\d+$/, '')
  return DOC_HOSTS.some((d) => h === d || h.endsWith('.' + d))
}

function normalize(s: string): string {
  return s.toLowerCase().replace(/\s+/g, ' ').trim()
}

function wordShingles(s: string, n: number): string[] {
  const words = normalize(s).split(' ').filter(Boolean)
  const out: string[] = []
  for (let i = 0; i + n <= words.length; i++) out.push(words.slice(i, i + n).join(' '))
  return out
}

const COMMON_FILENAMES = new Set([
  'package.json', 'package-lock.json', 'yarn.lock', 'pnpm-lock.yaml', 'requirements.txt',
  'go.mod', 'go.sum', 'gemfile', 'gemfile.lock', 'composer.json', 'composer.lock', 'pom.xml',
  'build.gradle', 'cargo.toml', 'dockerfile', 'docker-compose.yml', '.env', '.env.example',
  '.gitignore', 'index.js', 'index.ts', 'index.html', 'main.go', 'app.py', 'settings.py',
  'next.config.js', 'web.config', 'nginx.conf', '.htaccess', 'php.ini', 'tsconfig.json',
])

/**
 * Values taken from ONE user's request. If any of them shows up in text bound
 * for the shared cache, the text is user-specific and must not be shared.
 */
export interface UserValues {
  filePath?: string
  codeSnippet?: string
  surroundingCode?: string
  aboutYou?: string
  rawMessage?: string
}

function echoesUserValues(text: string, v: UserValues): string[] {
  const reasons: string[] = []
  const hay = normalize(text)
  if (v.filePath) {
    const p = normalize(v.filePath)
    const base = p.split(/[\\/]/).pop() ?? ''
    // A bare common file name (package.json, .env) is not user-specific.
    const bareCommon = !/[\\/]/.test(p) && COMMON_FILENAMES.has(p)
    if (!bareCommon && p.length >= 3 && hay.includes(p)) reasons.push('echo:file_path')
    else if (base.length >= 5 && /\.[a-z0-9]{1,8}$/.test(base) && !COMMON_FILENAMES.has(base) &&
             hay.includes(base)) reasons.push('echo:file_name')
  }
  for (const [name, code] of [['snippet', v.codeSnippet], ['surrounding_code', v.surroundingCode]] as const) {
    if (!code) continue
    const hit = code.split('\n').map(normalize).some((l) => l.length >= 16 && hay.includes(l))
    if (hit) reasons.push(`echo:${name}`)
  }
  if (v.aboutYou && wordShingles(v.aboutYou, 5).some((s) => hay.includes(s))) reasons.push('echo:about_you')
  if (v.rawMessage && wordShingles(v.rawMessage, 7).some((s) => hay.includes(s))) reasons.push('echo:scanner_message')
  return reasons
}

/** Pattern checks that apply to any text bound for a shared cache. */
export function findUserSpecificContent(text: string): string[] {
  const reasons: string[] = []
  for (const [name, re] of SECRET_PATTERNS) if (re.test(text)) reasons.push(`secret:${name}`)
  if (hasHighEntropyToken(text)) reasons.push('secret:high_entropy')
  // Redaction descriptors from the client (<SECRET: type, length, prefix, entropy>)
  // describe one user's secret, so they never belong in shared text.
  if (/<\s*SECRET\s*:/i.test(text)) reasons.push('secret:redaction_label')
  // URLs: documentation hosts are fine; anything else is probably the user's site.
  let withoutUrls = text
  for (const m of text.matchAll(URL_RE)) {
    if (!isDocHost(m[1])) reasons.push('url:non_doc_host')
    withoutUrls = withoutUrls.replace(m[0], ' ')
  }
  if (ABS_PATH.test(withoutUrls)) reasons.push('path:absolute')
  if (REL_PATH.test(withoutUrls)) reasons.push('path:relative')
  if (EMAIL.test(withoutUrls)) reasons.push('pii:email')
  for (const m of withoutUrls.matchAll(IPV4)) {
    const ip = m[0]
    if (m.slice(1, 5).every((o) => Number(o) <= 255) && !ALLOWED_IPS.has(ip) &&
        !ip.startsWith('10.') && !ip.startsWith('192.168.')) {
      reasons.push('pii:ip'); break
    }
  }
  if (CODE_FENCE.test(text)) reasons.push('code:fence')
  if (LONG_INLINE_CODE.test(text)) reasons.push('code:long_inline')
  if (CODE_LINE.test(text)) reasons.push('code:line')
  return [...new Set(reasons)]
}

/**
 * Gate for writing (and serving) a row of the shared explanation cache.
 * Returns ok=false if the explanation contains anything user-specific.
 */
export function checkSharedExplanation(
  s: { simply: string; actions: string[] },
  user: UserValues = {},
): SharedCacheCheck {
  if (typeof s?.simply !== 'string' || !Array.isArray(s.actions) ||
      s.actions.some((a) => typeof a !== 'string')) {
    return { ok: false, reasons: ['shape'] }
  }
  if (s.simply.length > 2000 || s.actions.length > 12 || s.actions.some((a) => a.length > 600)) {
    return { ok: false, reasons: ['too_long'] }
  }
  const text = [s.simply, ...s.actions].join('\n')
  const reasons = [...findUserSpecificContent(text), ...echoesUserValues(text, user)]
  return { ok: reasons.length === 0, reasons: [...new Set(reasons)] }
}

/**
 * Clean a short label (e.g. a finding title) before it goes into a prompt whose
 * output will be shared. Returns '' if it can't be made safe: callers then fall
 * back to the rule id alone.
 */
export function genericLabel(s: unknown, maxLen = 120): string {
  if (typeof s !== 'string') return ''
  const t = s.replace(/[\r\n\t]+/g, ' ').replace(/\s+/g, ' ').trim()
  if (!t || t.length > maxLen) return ''
  if (/["'`]/.test(t)) return ''               // quoted spans usually carry matched code
  if (/https?:\/\//i.test(t) || /[\\/]/.test(t.replace(/\b\w+\/\w+\b/g, ''))) return ''
  if (findUserSpecificContent(t).length > 0) return ''
  return t
}
