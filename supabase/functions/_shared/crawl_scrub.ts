// Crawl scrubbing for website test templates (dast-templates).
//
// Server-side copy of internal/dast/crawl_scrub.go. The CLI already scrubs, but
// old clients don't, so the server applies the same rules before it hashes,
// caches, logs or prompts with a crawl: each URL keeps scheme, host, port and
// path; query values are dropped (parameter names stay); the fragment and any
// user:password@ are dropped; id- and token-like path segments become
// placeholders. Both sides are checked against
// internal/dast/testdata/crawl_scrub_vectors.json.

export const SCRUB_VERSION = 'crawl-scrub-v1'

const MAX_ENDPOINTS = 200
const MAX_NAMES = 50
const MAX_NAME_LEN = 64
const MAX_HINT_LEN = 40
const MAX_TEMPLATES = 10

export interface DastEndpoint {
  url: string
  method: string
  formFields: string[]
  queryParams: string[]
}

export interface DastContext {
  targetURL: string
  endpoints: DastEndpoint[]
  techHints: string[]
  maxTemplates: number
}

const UUID_SEG = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/
const DIGITS_SEG = /^[0-9]+$/
const HEX_SEG = /^[0-9a-fA-F]{16,}$/
const SAFE_NAME = /^[A-Za-z0-9_.\[\]-]+$/
const SAFE_HINT = /^[a-z0-9._+-]+$/

/** True when s looks like a credential, session id or other opaque value. */
export function looksLikeToken(s: string): boolean {
  if (s.length >= 40) return true
  if (s.startsWith('eyJ') && s.length >= 16) return true
  if (HEX_SEG.test(s)) return true
  if (/[=+/%]/.test(s) && s.length >= 12) return true
  for (const part of s.split(/[-_.~]/)) {
    if (part.length >= 12 && /[0-9]/.test(part) && /[A-Za-z]/.test(part)) return true
    if (part.length >= 24) return true
    if (randomLetters(part) || shortMixedToken(part)) return true
  }
  return false
}

const VOWELS = new Set('aeiouyAEIOUY')

/**
 * A letters-only string of 16+ characters that looks random: camelCase pieces
 * averaging under 3 letters, or a long piece with under 20% vowels or a run of
 * 5+ consonants. Words and camelCase names survive. Matches Go RandomLetters.
 */
export function randomLetters(s: string): boolean {
  if (s.length < 16 || !/^[A-Za-z]+$/.test(s)) return false
  const pieces = s.match(/[A-Z]?[a-z]+|[A-Z]+/g) ?? []
  if (pieces.length > 0 && s.length / pieces.length < 3) return true
  for (const p of pieces) {
    if (p.length < 6) continue
    let vowels = 0, run = 0, maxRun = 0
    for (const c of p) {
      if (VOWELS.has(c)) { vowels++; run = 0 } else { run++; maxRun = Math.max(maxRun, run) }
    }
    if (maxRun >= 5 || vowels / p.length < 0.2) return true
  }
  return false
}

/** 0 lowercase, 1 uppercase, 2 digit, 3 anything else. */
export function charClass(c: string): number {
  if (c >= 'a' && c <= 'z') return 0
  if (c >= 'A' && c <= 'Z') return 1
  if (c >= '0' && c <= '9') return 2
  return 3
}

/**
 * An 8 to 11 character letters-and-digits string with 6+ switches between
 * lowercase, uppercase and digits (a code like aB3dE6gH9jK). Matches Go
 * ShortMixedToken.
 */
export function shortMixedToken(s: string): boolean {
  if (s.length < 8 || s.length > 11 || !/[0-9]/.test(s) || !/[A-Za-z]/.test(s)) return false
  let switches = 0, prev = -1
  for (const c of s) {
    const k = charClass(c)
    if (k === 3) return false
    if (prev >= 0 && k !== prev) switches++
    prev = k
  }
  return switches >= 6
}

/** Any "@" in a path segment: an email address or an @handle. */
export function looksLikeEmail(seg: string): boolean {
  return seg.includes('@')
}

const PERSON_PARENTS = new Set([
  'user', 'users', 'u', 'profile', 'profiles', 'people', 'person', 'member', 'members',
  'author', 'authors', 'staff', 'employee', 'employees', 'customer', 'customers',
  'contacts', 'student', 'students', 'patient', 'patients',
])

const ROUTE_WORDS = new Set([
  'new', 'me', 'edit', 'settings', 'search', 'list', 'all', 'index', 'create', 'login',
  'logout', 'signin', 'signup', 'register', 'sign_in', 'sign_up', 'sign-in', 'sign-up',
  'profile', 'account', 'admin', 'export', 'import', 'invite', 'invitations', 'password',
  'reset', 'verify', 'confirm', 'current', 'self', 'api', 'v1', 'v2', 'v3',
])

/** A route like /users or /u whose child is usually a person's handle or name. */
export function isPersonParent(seg: string): boolean {
  return PERSON_PARENTS.has(seg.toLowerCase())
}

/** After a person parent: anything but a number, a placeholder or a route word. */
export function looksLikePersonName(seg: string): boolean {
  if (!seg || seg.startsWith('{') || /^[0-9]+$/.test(seg)) return false
  return !ROUTE_WORDS.has(seg.toLowerCase())
}

/** Backslash or ASCII control character: parsers disagree, so drop the URL. */
export function hasUnsafeChar(s: string): boolean {
  return /[\\\x00-\x1f\x7f]/.test(s)
}

/**
 * Scrub decoded path segments in order, using the previous segment as
 * context for names. Matches Go ScrubPath.
 */
export function scrubPath(segs: string[]): string[] {
  const out: string[] = []
  let prev = ''
  for (let seg of segs) {
    const semi = seg.indexOf(';')
    if (semi >= 0) seg = seg.slice(0, semi)
    if (!seg || seg === '.' || seg === '..') continue
    let s = scrubSegment(seg)
    if (!s.startsWith('{') && isPersonParent(prev) && looksLikePersonName(seg)) s = '{name}'
    out.push(s)
    prev = seg
  }
  return out
}

/** Placeholder for an id- or token-like path segment, else the segment. */
export function scrubSegment(seg: string): string {
  if (!seg) return ''
  if (looksLikeEmail(seg)) return '{email}'
  if (UUID_SEG.test(seg)) return '{uuid}'
  if (DIGITS_SEG.test(seg)) return seg.length >= 10 ? '{num}' : seg
  if (looksLikeToken(seg)) return '{token}'
  return seg
}

/** Clean, dedupe and sort parameter or form field names. */
export function scrubNames(names: unknown): string[] {
  if (!Array.isArray(names)) return []
  const out = new Set<string>()
  for (const raw of names) {
    if (typeof raw !== 'string') continue
    const n = raw.trim()
    if (!n || n.length > MAX_NAME_LEN || !SAFE_NAME.test(n) || looksLikeToken(n)) continue
    out.add(n)
  }
  return [...out].sort(byCodeUnit).slice(0, MAX_NAMES)
}

// Same set of unescaped bytes as Go's url.PathEscape.
function pathEscape(s: string): string {
  let out = ''
  for (const b of new TextEncoder().encode(s)) {
    const c = String.fromCharCode(b)
    out += /[A-Za-z0-9\-_.~$&+=:@]/.test(c) ? c : '%' + b.toString(16).toUpperCase().padStart(2, '0')
  }
  return out
}

function safeDecode(s: string): string {
  try { return decodeURIComponent(s) } catch { return s }
}

/**
 * Scheme, host, port, scrubbed path and query parameter names only.
 * Returns '' for anything that isn't an absolute http(s) URL.
 */
export function scrubUrl(raw: unknown): string {
  if (typeof raw !== 'string') return ''
  const trimmed = raw.trim()
  if (hasUnsafeChar(trimmed)) return ''
  let u: URL
  try { u = new URL(trimmed) } catch { return '' }
  const scheme = u.protocol.replace(/:$/, '').toLowerCase()
  if ((scheme !== 'http' && scheme !== 'https') || !u.hostname) return ''
  let out = `${scheme}://${u.hostname.toLowerCase()}${u.port ? ':' + u.port : ''}`
  const path = u.pathname
  // Decode first, then split, so an encoded slash (%2F) splits segments the
  // same way Go's decoded url.Path does; scrubPath then cuts ;path=params.
  const decoded: string[] = []
  for (const raw of path.split('/')) decoded.push(...safeDecode(raw).split('/'))
  for (const s of scrubPath(decoded)) out += '/' + (s.startsWith('{') ? s : pathEscape(s))
  if (path.endsWith('/') && path !== '/') out += '/'
  const names: string[] = []
  for (const pair of u.search.replace(/^\?/, '').split('&')) {
    if (!pair) continue
    const eq = pair.indexOf('=')
    names.push(safeDecode((eq >= 0 ? pair.slice(0, eq) : pair).replace(/\+/g, ' ')))
  }
  const clean = scrubNames(names)
  if (clean.length) out += '?' + clean.join('=&') + '='
  return out
}

function byCodeUnit(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0
}

/**
 * Validate and scrub a request body. Anything malformed is dropped rather than
 * rejected, so old clients keep working; the result is always safe to hash,
 * store, log and put in a prompt.
 */
export function scrubContext(body: unknown): DastContext {
  const b = (body && typeof body === 'object') ? body as Record<string, unknown> : {}
  const merged = new Map<string, { method: string; url: string; q: string[]; f: string[] }>()
  for (const e of Array.isArray(b.endpoints) ? b.endpoints : []) {
    if (!e || typeof e !== 'object') continue
    const ep = e as Record<string, unknown>
    const url = scrubUrl(ep.url)
    if (!url) continue
    const method = typeof ep.method === 'string' && ep.method.trim().toUpperCase() === 'POST' ? 'POST' : 'GET'
    const key = `${method} ${url}`
    let a = merged.get(key)
    if (!a) { a = { method, url, q: [], f: [] }; merged.set(key, a) }
    if (Array.isArray(ep.queryParams)) a.q.push(...ep.queryParams.filter((x): x is string => typeof x === 'string'))
    if (Array.isArray(ep.formFields)) a.f.push(...ep.formFields.filter((x): x is string => typeof x === 'string'))
  }
  const endpoints = [...merged.keys()].sort(byCodeUnit).slice(0, MAX_ENDPOINTS).map(k => {
    const a = merged.get(k)!
    return { url: a.url, method: a.method, formFields: scrubNames(a.f), queryParams: scrubNames(a.q) }
  })
  const hints = new Set<string>()
  for (const h of Array.isArray(b.techHints) ? b.techHints : []) {
    if (typeof h !== 'string') continue
    const v = h.trim().toLowerCase()
    if (v && v.length <= MAX_HINT_LEN && SAFE_HINT.test(v)) hints.add(v)
  }
  const m = typeof b.maxTemplates === 'number' && Number.isInteger(b.maxTemplates) ? b.maxTemplates : 0
  return {
    targetURL: scrubUrl(b.targetURL),
    endpoints,
    techHints: [...hints].sort(byCodeUnit),
    maxTemplates: m <= 0 || m > MAX_TEMPLATES ? MAX_TEMPLATES : m,
  }
}

/** Canonical text the cache key is computed over (matches Go CrawlKey). */
export function canonicalCrawl(ctx: DastContext): string {
  let s = `${SCRUB_VERSION}\ntarget ${ctx.targetURL}\nmax ${ctx.maxTemplates}\n`
  for (const e of ctx.endpoints) {
    s += `ep ${e.method} ${e.url} q=${e.queryParams.join(',')} f=${e.formFields.join(',')}\n`
  }
  return s + `hints ${ctx.techHints.join(',')}\n`
}

/** sha256 hex of the scrubbed crawl. Pass the output of scrubContext. */
export async function crawlKey(ctx: DastContext): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(canonicalCrawl(ctx)))
  return Array.from(new Uint8Array(digest), b => b.toString(16).padStart(2, '0')).join('')
}
