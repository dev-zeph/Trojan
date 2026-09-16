// Sentry wire protocol: envelope parse/serialize, DSN parsing, body decoding.
//
// Envelope format is newline-delimited JSON:
//
//   {"event_id":"...","dsn":"...","sent_at":"..."}\n
//   {"type":"event","length":123}\n
//   <123 bytes of payload>\n
//   {"type":"attachment"}\n
//   <payload runs to the next newline>\n
//
// Two things bite here and are handled explicitly below:
//   1. `length` is a BYTE count, not a character count. Everything slices on a
//      Buffer; treating it as a string offset corrupts any multibyte payload.
//   2. `length` may be absent, in which case the item runs to the next newline.

import { brotliDecompressSync, gunzipSync, inflateSync } from 'node:zlib'

export interface EnvelopeHeader {
  event_id?: string
  dsn?: string
  sent_at?: string
  [key: string]: unknown
}

export interface EnvelopeItemHeader {
  type?: string
  length?: number
  content_type?: string
  [key: string]: unknown
}

export interface EnvelopeItem {
  header: EnvelopeItemHeader
  payload: Buffer
}

export interface Envelope {
  header: EnvelopeHeader
  items: EnvelopeItem[]
}

const NEWLINE = 0x0a

/** Decompress a request body based on its content-encoding. Never throws. */
export function decodeBody(body: Buffer, contentEncoding: string | undefined): Buffer {
  const enc = (contentEncoding ?? '').trim().toLowerCase()
  if (!enc || enc === 'identity') return body
  try {
    if (enc === 'gzip' || enc === 'x-gzip') return gunzipSync(body)
    if (enc === 'deflate') return inflateSync(body)
    if (enc === 'br') return brotliDecompressSync(body)
  } catch (err) {
    console.error(`[errors] failed to decompress ${enc} body, using raw bytes:`, String(err))
  }
  return body
}

function readLine(buf: Buffer, start: number): { line: Buffer; next: number } | null {
  if (start >= buf.length) return null
  const idx = buf.indexOf(NEWLINE, start)
  if (idx === -1) return { line: buf.subarray(start), next: buf.length }
  return { line: buf.subarray(start, idx), next: idx + 1 }
}

export function parseEnvelope(buf: Buffer): Envelope {
  const first = readLine(buf, 0)
  if (!first) throw new Error('empty envelope')

  let header: EnvelopeHeader
  try {
    header = JSON.parse(first.line.toString('utf8')) as EnvelopeHeader
  } catch {
    throw new Error('envelope header is not valid JSON')
  }

  const items: EnvelopeItem[] = []
  let pos = first.next

  while (pos < buf.length) {
    const headerLine = readLine(buf, pos)
    if (!headerLine) break
    // trailing newline at the end of the envelope
    if (headerLine.line.length === 0) {
      pos = headerLine.next
      continue
    }

    let itemHeader: EnvelopeItemHeader
    try {
      itemHeader = JSON.parse(headerLine.line.toString('utf8')) as EnvelopeItemHeader
    } catch {
      // Not a parseable item header — stop rather than mangle the rest.
      break
    }
    pos = headerLine.next

    let payload: Buffer
    if (typeof itemHeader.length === 'number' && itemHeader.length >= 0) {
      // BYTE count — slice the Buffer, not a string.
      const end = Math.min(pos + itemHeader.length, buf.length)
      payload = buf.subarray(pos, end)
      pos = end
      if (pos < buf.length && buf[pos] === NEWLINE) pos++
    } else {
      const payloadLine = readLine(buf, pos)
      if (!payloadLine) {
        payload = Buffer.alloc(0)
        pos = buf.length
      } else {
        payload = payloadLine.line
        pos = payloadLine.next
      }
    }

    items.push({ header: itemHeader, payload })
  }

  return { header, items }
}

/**
 * Re-serialize an envelope. `length` is always recomputed from the actual
 * payload byte length — rewriting an event (scrubbing, tagging) changes its
 * size, and a stale `length` silently truncates the event at the backend.
 */
export function serializeEnvelope(env: Envelope): Buffer {
  const chunks: Buffer[] = []
  chunks.push(Buffer.from(JSON.stringify(env.header), 'utf8'), Buffer.from('\n'))
  for (const item of env.items) {
    const header: EnvelopeItemHeader = { ...item.header, length: item.payload.length }
    chunks.push(Buffer.from(JSON.stringify(header), 'utf8'), Buffer.from('\n'))
    chunks.push(item.payload, Buffer.from('\n'))
  }
  return Buffer.concat(chunks)
}

/** Build a single-item envelope around a bare event (legacy /store/ bridge). */
export function envelopeFromEvent(header: EnvelopeHeader, event: unknown): Envelope {
  const payload = Buffer.from(JSON.stringify(event), 'utf8')
  return {
    header,
    items: [{ header: { type: 'event', length: payload.length }, payload }],
  }
}

// ---------------------------------------------------------------------------
// DSN + auth
// ---------------------------------------------------------------------------

export interface ParsedDsn {
  publicKey: string
  host: string
  protocol: string
  projectId: string
}

export function parseDsn(dsn: string): ParsedDsn | null {
  try {
    const u = new URL(dsn)
    const projectId = u.pathname.replace(/^\/+/, '').replace(/\/+$/, '')
    if (!u.username || !projectId) return null
    return {
      publicKey: u.username,
      host: u.host,
      protocol: u.protocol.replace(':', ''),
      projectId,
    }
  } catch {
    return null
  }
}

/**
 * Extract the public key from either the `sentry_key` query param or the
 * `X-Sentry-Auth: Sentry sentry_key=..., sentry_version=7` header.
 */
export function extractSentryKey(
  url: URL,
  headers: Record<string, string | string[] | undefined>,
): string | null {
  const fromQuery = url.searchParams.get('sentry_key')
  if (fromQuery) return fromQuery

  const raw = headers['x-sentry-auth']
  const authHeader = Array.isArray(raw) ? raw[0] : raw
  if (authHeader) {
    const match = /sentry_key\s*=\s*([^,\s]+)/i.exec(authHeader)
    if (match && match[1]) return match[1]
  }

  // Some SDKs fall back to the standard Authorization header for Sentry auth.
  const rawAuth = headers['authorization']
  const auth = Array.isArray(rawAuth) ? rawAuth[0] : rawAuth
  if (auth && /sentry/i.test(auth)) {
    const match = /sentry_key\s*=\s*([^,\s]+)/i.exec(auth)
    if (match && match[1]) return match[1]
  }

  return null
}

/** Sentry event ids are 32 hex chars; some APIs hand them back dashed. */
export function normalizeEventId(id: string | undefined | null): string {
  return (id ?? '').replace(/-/g, '').toLowerCase()
}
