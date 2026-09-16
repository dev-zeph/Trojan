// PII scrubbing — CONTRACT.md §A "PII scrubbing (applied before anything is stored)".
//
// Runs on the event BEFORE it is forwarded, so the storage backend never sees
// the secret at all. Every redacted field path is appended to a `trojan_scrubbed`
// list on the event so the UI can be honest about what was dropped.

export const REDACTED = '[redacted]'

/** Headers dropped outright regardless of value. */
const SENSITIVE_HEADERS = new Set([
  'authorization',
  'cookie',
  'set-cookie',
  'x-api-key',
  'proxy-authorization',
])

/** Key names that mean "this is a secret" wherever they appear. */
const SENSITIVE_KEY_RE = /pass|secret|token|auth|key|cred|session/i

/** Value-level patterns, applied to messages and frame-local vars. */
const EMAIL_RE = /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g
const CARD_RE = /\b(?:\d[ -]?){13,19}\b/g
const LONG_TOKEN_RE = /\b[A-Za-z0-9_\-]{32,}\b/g
const BEARER_PREFIX_RE = /\b(bearer|token|basic)\s+\S+/gi

const MAX_DEPTH = 12

export interface ScrubResult {
  scrubbed: string[]
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v)
}

/** Redact secret-shaped values inside a free-text string. */
export function redactValue(input: string): { value: string; changed: boolean } {
  let out = input
  out = out.replace(BEARER_PREFIX_RE, (m) => `${m.split(/\s+/)[0]} ${REDACTED}`)
  out = out.replace(EMAIL_RE, REDACTED)
  out = out.replace(CARD_RE, (m) => {
    // Require enough actual digits to look like a card/account number.
    const digits = m.replace(/\D/g, '')
    return digits.length >= 13 && digits.length <= 19 ? REDACTED : m
  })
  out = out.replace(LONG_TOKEN_RE, (m) => (m === REDACTED ? m : REDACTED))
  return { value: out, changed: out !== input }
}

interface WalkOpts {
  /** apply value-level redaction to strings, not just key-name matching */
  redactValues: boolean
}

/**
 * Recursively scrub a container in place.
 * `path` is the dotted field path recorded in `trojan_scrubbed`.
 */
function walk(node: unknown, path: string, out: string[], opts: WalkOpts, depth: number): void {
  if (depth > MAX_DEPTH) return

  if (Array.isArray(node)) {
    for (let i = 0; i < node.length; i++) {
      const child = node[i]
      if (typeof child === 'string' && opts.redactValues) {
        const r = redactValue(child)
        if (r.changed) {
          node[i] = r.value
          out.push(`${path}.${i}`)
        }
      } else {
        walk(child, `${path}.${i}`, out, opts, depth + 1)
      }
    }
    return
  }

  if (!isPlainObject(node)) return

  for (const key of Object.keys(node)) {
    const childPath = path ? `${path}.${key}` : key
    const value = node[key]

    if (SENSITIVE_KEY_RE.test(key)) {
      if (value !== REDACTED && value !== undefined && value !== null) {
        node[key] = REDACTED
        out.push(childPath)
      }
      continue
    }

    if (typeof value === 'string') {
      if (opts.redactValues) {
        const r = redactValue(value)
        if (r.changed) {
          node[key] = r.value
          out.push(childPath)
        }
      }
      continue
    }

    walk(value, childPath, out, opts, depth + 1)
  }
}

function scrubHeaders(headers: unknown, path: string, out: string[]): void {
  if (!isPlainObject(headers)) return
  for (const key of Object.keys(headers)) {
    const lower = key.toLowerCase()
    if (SENSITIVE_HEADERS.has(lower) || SENSITIVE_KEY_RE.test(key)) {
      if (headers[key] !== REDACTED) {
        headers[key] = REDACTED
        out.push(`${path}.${key}`)
      }
      continue
    }
    const value = headers[key]
    if (typeof value === 'string') {
      const r = redactValue(value)
      if (r.changed) {
        headers[key] = r.value
        out.push(`${path}.${key}`)
      }
    }
  }
}

/**
 * Scrub a Sentry event payload in place. Returns the list of redacted paths,
 * which is also written onto the event as `trojan_scrubbed` (top level) and
 * `extra.trojan_scrubbed` (belt and braces — some backends drop unknown
 * top-level keys but every backend preserves `extra`).
 */
export function scrubEvent(event: Record<string, unknown>): ScrubResult {
  const scrubbed: string[] = []

  // --- request context -----------------------------------------------------
  const request = event['request']
  if (isPlainObject(request)) {
    scrubHeaders(request['headers'], 'request.headers', scrubbed)

    if (request['cookies'] !== undefined && request['cookies'] !== null) {
      request['cookies'] = REDACTED
      scrubbed.push('request.cookies')
    }

    for (const field of ['data', 'query_string', 'env'] as const) {
      const value = request[field]
      if (typeof value === 'string') {
        const r = redactValue(value)
        if (r.changed) {
          request[field] = r.value
          scrubbed.push(`request.${field}`)
        }
      } else if (value !== undefined && value !== null) {
        walk(value, `request.${field}`, scrubbed, { redactValues: true }, 0)
      }
    }
  }

  // --- extra ---------------------------------------------------------------
  const extra = event['extra']
  if (extra !== undefined && extra !== null) {
    walk(extra, 'extra', scrubbed, { redactValues: true }, 0)
  }

  // --- user ----------------------------------------------------------------
  const user = event['user']
  if (isPlainObject(user)) {
    walk(user, 'user', scrubbed, { redactValues: true }, 0)
  }

  // --- messages ------------------------------------------------------------
  const message = event['message']
  if (typeof message === 'string') {
    const r = redactValue(message)
    if (r.changed) {
      event['message'] = r.value
      scrubbed.push('message')
    }
  } else if (isPlainObject(message)) {
    walk(message, 'message', scrubbed, { redactValues: true }, 0)
  }

  const logentry = event['logentry']
  if (isPlainObject(logentry)) {
    walk(logentry, 'logentry', scrubbed, { redactValues: true }, 0)
  }

  // --- exceptions: values + frame-local vars -------------------------------
  const exception = event['exception']
  const values = isPlainObject(exception) ? exception['values'] : undefined
  if (Array.isArray(values)) {
    for (let vi = 0; vi < values.length; vi++) {
      const exc = values[vi]
      if (!isPlainObject(exc)) continue

      const excValue = exc['value']
      if (typeof excValue === 'string') {
        const r = redactValue(excValue)
        if (r.changed) {
          exc['value'] = r.value
          scrubbed.push(`exception.values.${vi}.value`)
        }
      }

      const stacktrace = exc['stacktrace']
      const frames = isPlainObject(stacktrace) ? stacktrace['frames'] : undefined
      if (!Array.isArray(frames)) continue

      for (let fi = 0; fi < frames.length; fi++) {
        const frame = frames[fi]
        if (!isPlainObject(frame)) continue
        const vars = frame['vars']
        if (vars !== undefined && vars !== null) {
          walk(
            vars,
            `exception.values.${vi}.stacktrace.frames.${fi}.vars`,
            scrubbed,
            { redactValues: true },
            0,
          )
        }
      }
    }
  }

  // --- breadcrumbs ---------------------------------------------------------
  const breadcrumbs = event['breadcrumbs']
  const crumbList = Array.isArray(breadcrumbs)
    ? breadcrumbs
    : isPlainObject(breadcrumbs) && Array.isArray(breadcrumbs['values'])
      ? (breadcrumbs['values'] as unknown[])
      : null
  if (crumbList) {
    walk(crumbList, 'breadcrumbs', scrubbed, { redactValues: true }, 0)
  }

  // --- record what we dropped ---------------------------------------------
  const unique = [...new Set(scrubbed)].sort()
  event['trojan_scrubbed'] = unique
  const existingExtra = event['extra']
  if (isPlainObject(existingExtra)) {
    existingExtra['trojan_scrubbed'] = unique
  } else {
    event['extra'] = { trojan_scrubbed: unique }
  }

  return { scrubbed: unique }
}

/** Read the scrub list back off a stored event payload. */
export function readScrubbed(data: Record<string, unknown> | undefined): string[] {
  if (!data) return []
  const top = data['trojan_scrubbed']
  if (Array.isArray(top)) return top.map(String)
  const extra = data['extra']
  if (isPlainObject(extra) && Array.isArray(extra['trojan_scrubbed'])) {
    return (extra['trojan_scrubbed'] as unknown[]).map(String)
  }
  return []
}
