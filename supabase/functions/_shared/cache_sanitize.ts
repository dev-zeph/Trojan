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
// Exact hosts only (plus www.): a whole vendor domain such as github.com would
// let any user's repository URL through.
const DOC_HOSTS = [
  'owasp.org', 'cheatsheetseries.owasp.org', 'cwe.mitre.org', 'cve.mitre.org', 'cve.org',
  'nvd.nist.gov', 'developer.mozilla.org', 'semgrep.dev', 'docs.github.com', 'osv.dev',
  'portswigger.net', 'datatracker.ietf.org', 'nodejs.org', 'docs.python.org', 'go.dev',
  'pkg.go.dev', 'php.net', 'learn.microsoft.com', 'docs.aws.amazon.com', 'docs.stripe.com',
  'nextjs.org', 'expressjs.com',
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
// Any absolute path with two or more segments, extension or not (/app/src/x,
// /users/alice/acme). Well-known system paths used in generic explanations of
// path traversal are allowed.
const ABS_PATH_ANY = /(?:^|[\s"'`(=:])(\/[\w.-]+(?:\/[\w.-]+)+)\/?/g
const SYSTEM_PATHS = new Set([
  '/etc/passwd', '/etc/shadow', '/etc/hosts', '/proc/self/environ', '/dev/null', '/dev/urandom',
  '/.well-known/security.txt', '/var/run/docker.sock',
])
// Windows drive paths with either slash, even right after a colon (File:C:\x),
// and UNC shares (\\server\share).
const WIN_PATH = /(?<![A-Za-z])[A-Za-z]:[\\/][\w$.-]+/
const UNC_PATH = /\\\\[\w.$-]+\\[\w.$-]+/
// Extensionless project paths under a common top-level folder (src/payments-settings).
// Lower-case folder and next segment only, so prose like "app/API" or "CI/CD" passes.
const PROJECT_DIR_PATH = /\b(?:src|app|lib|libs|config|configs|api|routes|server|public|pages|components|internal|cmd|pkg|scripts|services|controllers|models|handlers|deploy|infra)\/[a-z0-9_.-]*[a-z0-9_-][a-z0-9_./-]*/
// A bare, project-specific source file name: has a dash or underscore and a code extension.
const CUSTOM_SOURCE_FILE = /\b[\w]+[-_][\w-]*\.(?:ts|tsx|js|jsx|mjs|cjs|py|go|rb|php|java|cs|kt|swift|rs|vue|svelte)\b/
// A relative path with at least one directory and a file extension: src/a/b.ts
const REL_PATH = /\b(?:[\w@.-]+\/)+[\w.-]+\.[A-Za-z0-9]{1,8}\b/
const URL_RE = /\bhttps?:\/\/([^\s/"'`)<>]+)[^\s"'`)<>]*/gi
// Bare host names ("shop.example-store.ca"): a dotted name ending in a known TLD.
// The TLD must be lower case, so product names like "ASP.NET" or "Socket.IO"
// written in their usual case don't match. TLDs that double as common file
// extensions (py, sh, rs, md, pl, cc, in, so ...) are left out on purpose:
// "settings.py" is a file name, not a host. File paths are caught separately.
const HOST_TLDS = [
  'com', 'net', 'org', 'io', 'dev', 'app', 'ai', 'co', 'ca', 'uk', 'us', 'de', 'fr', 'nl', 'es',
  'au', 'nz', 'jp', 'br', 'mx', 'eu', 'ch', 'se', 'me', 'tech', 'cloud', 'xyz', 'info', 'biz',
  'site', 'online', 'store', 'shop', 'page', 'tv', 'fm', 'gg', 'ly', 'agency', 'studio', 'health',
]
const BARE_HOST = new RegExp(
  `(?<![\\w@.-])((?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\\.)+(?:${HOST_TLDS.join('|')}))(?![\\w-]|\\.[A-Za-z0-9])`,
  'g',
)
const FULL_HOST = new RegExp(`^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)+(?:${HOST_TLDS.join('|')})$`)

// Host-shaped names that are product or framework names in normal prose, plus
// reserved example domains. Compared lower-cased.
const HOST_NAME_ALLOW = new Set([
  'asp.net', 'ado.net', 'vb.net', 'socket.io', 'example.com', 'example.org', 'example.net',
])

/** Bare host names in text, excluding docs hosts and product names. Lower-cased. */
export function findBareHosts(text: string): string[] {
  const out: string[] = []
  for (const m of text.matchAll(BARE_HOST)) {
    const h = m[1].toLowerCase()
    if (HOST_NAME_ALLOW.has(h) || isDocHost(h)) continue
    out.push(h)
  }
  return [...new Set(out)]
}

/** Hosts this request is about: from any URL in its fields, or a bare host as the file path. */
export function requestHosts(v: UserValues): string[] {
  const hosts = new Set<string>()
  for (const field of [v.filePath, v.rawMessage, v.codeSnippet, v.surroundingCode]) {
    if (!field) continue
    for (const m of field.matchAll(URL_RE)) {
      const h = m[1].toLowerCase().replace(/^[^@]*@/, '').replace(/:\d+$/, '')
      if (h.includes('.')) hosts.add(h)
    }
  }
  // A website finding whose "file" is a bare host. Only names ending in a known
  // TLD count, so file names like package.json or settings.py are not hosts.
  const fp = v.filePath?.trim().toLowerCase().replace(/:\d+$/, '') ?? ''
  if (FULL_HOST.test(fp)) hosts.add(fp)
  for (const h of [...hosts]) if (h.startsWith('www.')) hosts.add(h.slice(4))
  return [...hosts]
}

const EMAIL = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/
const IPV4 = /\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b/g
const ALLOWED_IPS = new Set(['127.0.0.1', '0.0.0.0', '169.254.169.254', '255.255.255.255'])
const CODE_FENCE = /```|~~~/
const LONG_INLINE_CODE = /`[^`\n]{61,}`/
// Short inline code that is clearly code: a call with arguments, an assignment,
// string concatenation. `innerHTML` or `npm audit fix` pass.
const CODE_SPAN = /`[^`\n]*(?:\w\([^`\n]*[\w"')]\)|\s=\s|=\s*["'[{]|["'] *\+|\+ *["'])[^`\n]*`/
// A dotted call whose argument is itself a dotted name: res.send(req.query.name).
const DOTTED_CALL = /\b[A-Za-z_$][\w$]*(?:\.[\w$]+)+\(\s*[A-Za-z_$][\w$]*(?:\.[\w$]+|\[)[^()]*\)/
// snake_case or camelCase assignment: api_key = os.environ[...], apiKey = "x".
const ASSIGNMENT = /\b(?:[a-z]+_[a-z0-9_]+|[a-z]+[A-Z][A-Za-z0-9]*)\s*=\s*(?:["'`\[{(]|[\w$.]+[.([])/
// SQL in any case, written as a statement.
const SQL_STMT = /\b(?:select\s+(?:\*|[\w,\s.]+?)\s+from\s+\w+\s+where\b|select\s+\*\s+from\b|insert\s+into\s+\w+\s*\(|update\s+\w+\s+set\s+\w+\s*=|delete\s+from\s+\w+\s+where\s+\w+\s*=)/i
// Hex runs of 32+ (API secrets, git SHAs): entropy can't flag them (max 4 bits/char).
const HEX_RUN = /\b(?=[0-9a-f]*[a-f])(?=[0-9a-f]*\d)[0-9a-f]{32,}\b|\b(?=[0-9A-F]*[A-F])(?=[0-9A-F]*\d)[0-9A-F]{32,}\b/
// Plain password-like values right after the word password: "password hunter2".
const PASSWORD_VALUE = /\b(?:password|passwd|pwd|passphrase)\b\s*(?:is\s+|=\s*|:\s*)?["'`]?(?=[^\s"'`]*\d)(?=[^\s"'`]*[A-Za-z])[^\s"'`.,;]{4,}/i
// IPv6: hex groups joined by colons. Counted as an address only with "::" or
// 5+ colons, so clock times (10:30:00) and ratios don't match.
const IPV6_CANDIDATE = /(?<![\w:])[0-9a-f]{0,4}(?::[0-9a-f]{0,4}){2,7}(?![\w:])/gi
function hasIpv6(text: string): boolean {
  for (const m of text.matchAll(IPV6_CANDIDATE)) {
    const t = m[0]
    if (!/[0-9a-f]/i.test(t) || t === '::1' || /^:+$/.test(t)) continue
    if (t.includes('::') || (t.match(/:/g) ?? []).length >= 5) return true
  }
  return false
}
const PHONE = /\b\d{3}[-. ]\d{3}[-. ]\d{4}\b/
// A scoped npm package (@company/pkg) names the organisation that published it.
const SCOPED_PACKAGE = /(?<![\w.])@[a-z0-9][\w.-]*\/[a-z0-9][\w.-]*/i
const SCOPED_PACKAGE_ALLOW = /^@(?:types|babel|angular|nestjs|aws-sdk|google-cloud|azure|vue|sveltejs|remix-run|tanstack|supabase|prisma|octokit|next|sentry|apollo|fastify|hapi|nuxt|mui|emotion|testing-library|playwright|firebase|clerk|vercel|auth|trpc|reduxjs|grpc|hono)\//i
// Telling the reader to take something somewhere: the classic phishing pattern
// ("paste your key at keycheck.example to verify"). Commands in their own
// terminal are fine and don't match.
const HOSTISH = `(?:https?:\\/\\/|www\\.|[a-z0-9-]+(?:\\.[a-z0-9-]+)*\\.(?:${HOST_TLDS.join('|')})\\b)`
const INSTR_VISIT = new RegExp(`\\b(?:visit|go to|navigate to|browse to|head to|head over to|open|check)\\s+(?:the\\s+)?(?:site\\s+|page\\s+|website\\s+)?${HOSTISH}`, 'i')
const INSTR_SEND = new RegExp(
  `\\b(?:paste|upload|send|submit|enter|share|email|post|type|forward|provide)\\b[^!?\\n]{0,60}?\\b(?:at|to|into|on|in|via|using|with)\\s+` +
  `(?:a |an |the |this |that |our |any )?(?:${HOSTISH}|(?:[\\w-]+\\s){0,2}(?:website|web site|site|online|form|chat|forum|third[- ]party|support|checker|validator|verifier|decoder)\\b)`,
  'i',
)
// A line that reads like source code rather than prose (statements, braces, assignments).
// Case-sensitive on purpose: prose sentences start with a capital ("Return a 404 ...").
const CODE_LINE = /(?:;\s*$|^\s*(?:const|let|var|function|def|import|return|SELECT|INSERT|UPDATE|DELETE)\s.*[=({;]|^\s*if\s*\(.*\)\s*\{|\{\s*$|=>\s*\{)/m

/**
 * True if a sentence tells the reader to visit a site, or to paste, upload or
 * send something to a site, form, online tool or support chat. Sentences that
 * warn against it ("Never paste your key into an online decoder") are fine.
 */
export function hasSendOrVisitInstruction(text: string): boolean {
  for (const sentence of text.split(/(?<=[.!?])\s+|\n+/)) {
    if (/\b(?:never|don't|do not|not|avoid|instead of)\b/i.test(sentence)) continue
    if (INSTR_VISIT.test(sentence) || INSTR_SEND.test(sentence)) return true
  }
  return false
}

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
  for (const m of text.matchAll(/[A-Za-z0-9+/_=-]{20,}/g)) {
    const t = m[0]
    const classes = [/[a-z]/, /[A-Z]/, /[0-9]/].filter((r) => r.test(t)).length
    // 32+ chars: two character classes are enough. Shorter: require all three
    // (lower, upper, digit), so long CamelCase words (SecurityConfiguration) pass.
    if (t.length >= 32 && classes >= 2 && shannonEntropy(t) >= 4.0) return true
    if (classes === 3 && shannonEntropy(t) >= 3.5) return true
  }
  return false
}

function isDocHost(host: string): boolean {
  const h = host.toLowerCase().replace(/:\d+$/, '').replace(/^www\./, '')
  return DOC_HOSTS.includes(h)
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

/**
 * "About you" echoes: any 5-word run, the whole text when it is shorter than 5
 * words, and any run of 2+ capitalised words in it (a company or product name).
 */
export function aboutYouEchoed(aboutYou: string, hayNormalized: string): boolean {
  const words = normalize(aboutYou).split(' ').filter(Boolean)
  if (words.length >= 2 && words.length < 5) {
    const whole = words.join(' ')
    if (whole.length >= 6 && hayNormalized.includes(whole)) return true
  }
  if (wordShingles(aboutYou, 5).some((s) => hayNormalized.includes(s))) return true
  for (const m of aboutYou.matchAll(/\b[A-Z][\w&'-]*(?:\s+[A-Z][\w&'-]*)+/g)) {
    const name = normalize(m[0]).replace(/^(?:i|i'm|we|my|our)\s+/, '')
    if (name.split(' ').length >= 2 && name.length >= 6 && hayNormalized.includes(name)) return true
  }
  return false
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
    // Extensionless, project-specific names (payments-settings) and the stem of a file name.
    else {
      const stem = base.replace(/\.[a-z0-9]{1,8}$/, '')
      if (stem.length >= 6 && /[-_]/.test(stem) && hay.includes(stem)) reasons.push('echo:file_name')
    }
  }
  for (const [name, code] of [['snippet', v.codeSnippet], ['surrounding_code', v.surroundingCode]] as const) {
    if (!code) continue
    const hit = code.split('\n').map(normalize).some((l) =>
      (l.length >= 16 || (l.length >= 10 && /[=();{}]/.test(l))) && hay.includes(l))
    if (hit) reasons.push(`echo:${name}`)
  }
  // The request's own target host, in any form (URL, bare name, any case).
  if (requestHosts(v).some((h) => h.length >= 4 && hay.includes(h))) reasons.push('echo:target_host')
  if (v.aboutYou && aboutYouEchoed(v.aboutYou, hay)) reasons.push('echo:about_you')
  if (v.rawMessage && wordShingles(v.rawMessage, 6).some((s) => hay.includes(s))) reasons.push('echo:scanner_message')
  return reasons
}

/** Pattern checks that apply to any text bound for a shared cache. */
export function findUserSpecificContent(text: string): string[] {
  const reasons: string[] = []
  for (const [name, re] of SECRET_PATTERNS) if (re.test(text)) reasons.push(`secret:${name}`)
  // Documentation URLs carry long page slugs (SQL_Injection_Prevention_Cheat_Sheet),
  // so the entropy check skips them. Key patterns above still see the full text.
  const textWithoutDocUrls = text.replace(URL_RE, (u, host) => (isDocHost(host) ? ' ' : u))
  if (hasHighEntropyToken(textWithoutDocUrls)) reasons.push('secret:high_entropy')
  // Redaction labels from the client (<SECRET removed by Trojan: type=..., ...>,
  // and the older <SECRET: ...> form)
  // describe one user's secret, so they never belong in shared text.
  if (/<\s*SECRET\b/i.test(text)) reasons.push('secret:redaction_label')
  // URLs: documentation hosts are fine; anything else is probably the user's site.
  let withoutUrls = text
  for (const m of text.matchAll(URL_RE)) {
    if (!isDocHost(m[1])) reasons.push('url:non_doc_host')
    withoutUrls = withoutUrls.replace(m[0], ' ')
  }
  // Well-known system paths are generic; take them out before the path checks.
  for (const p of SYSTEM_PATHS) withoutUrls = withoutUrls.split(p).join(' ')
  if (ABS_PATH.test(withoutUrls) || WIN_PATH.test(withoutUrls) || UNC_PATH.test(withoutUrls)) reasons.push('path:absolute')
  for (const m of withoutUrls.matchAll(ABS_PATH_ANY)) {
    if (!SYSTEM_PATHS.has(m[1].toLowerCase())) { reasons.push('path:absolute'); break }
  }
  if (PROJECT_DIR_PATH.test(withoutUrls) || CUSTOM_SOURCE_FILE.test(withoutUrls)) reasons.push('path:relative')
  if (REL_PATH.test(withoutUrls)) reasons.push('path:relative')
  if (EMAIL.test(withoutUrls)) reasons.push('pii:email')
  if (findBareHosts(withoutUrls).length > 0) reasons.push('host:bare')
  for (const m of withoutUrls.matchAll(IPV4)) {
    const ip = m[0]
    // CIDR ranges (10.0.0.0/8) are generic network advice; single hosts are not.
    const cidr = withoutUrls.slice((m.index ?? 0) + ip.length).startsWith('/')
    if (m.slice(1, 5).every((o) => Number(o) <= 255) && !ALLOWED_IPS.has(ip) && !cidr) {
      reasons.push('pii:ip'); break
    }
  }
  if (hasIpv6(withoutUrls)) reasons.push('pii:ip')
  if (PHONE.test(withoutUrls)) reasons.push('pii:phone')
  for (const m of withoutUrls.matchAll(new RegExp(SCOPED_PACKAGE, 'gi'))) {
    if (!SCOPED_PACKAGE_ALLOW.test(m[0])) { reasons.push('package:scoped'); break }
  }
  if (HEX_RUN.test(text)) reasons.push('secret:hex')
  if (PASSWORD_VALUE.test(text)) reasons.push('secret:password')
  if (hasSendOrVisitInstruction(text)) reasons.push('instruction:send_or_visit')
  if (CODE_FENCE.test(text)) reasons.push('code:fence')
  if (LONG_INLINE_CODE.test(text)) reasons.push('code:long_inline')
  if (CODE_LINE.test(text) || DOTTED_CALL.test(text) || ASSIGNMENT.test(text) || SQL_STMT.test(text)) reasons.push('code:line')
  if (CODE_SPAN.test(text)) reasons.push('code:inline')
  return [...new Set(reasons)]
}

/**
 * Gate for the shared explanation cache. Returns ok=false if the explanation
 * contains anything user-specific.
 * - On WRITE pass the requester's values: their own path, snippet, profile and
 *   host must not appear in text everyone will see.
 * - On READ pass no user values: a stored row is judged on its own content only,
 *   so a requester can't make a good shared row look bad (and force a rewrite)
 *   by sending a path that happens to appear in it.
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
