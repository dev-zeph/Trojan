import { assert, assertEquals, assertFalse, assertRejects } from 'jsr:@std/assert@1'
import { scrubContext } from './crawl_scrub.ts'
import {
  type CacheClient, expiryCutoff, getCachedTemplates, isExpired, purgeExpiredTemplates,
  saveCachedTemplates, TEMPLATE_CACHE_TTL_MS, userCrawlKey,
} from './template_cache.ts'

const quiet = async (fn: () => Promise<void>) => {
  const orig = console.error
  console.error = () => {}
  try { await fn() } finally { console.error = orig }
}

// In-memory stand-in for the table, enforcing unique (created_by, crawl_hash).
function fakeDb(opts: { failRead?: boolean; failWrite?: boolean; failDelete?: boolean } = {}) {
  const rows: Record<string, unknown>[] = []
  const calls: string[] = []
  const db: CacheClient = {
    from(table: string) {
      calls.push(`from ${table}`)
      return {
        select(_cols: string) {
          const f: [string, string][] = []
          const q = {
            eq(c: string, v: string) {
              f.push([c, v])
              return f.length === 2 ? { maybeSingle: () => {
                calls.push(`select ${f.map(([k]) => k).join(',')}`)
                if (opts.failRead) return Promise.resolve({ data: null, error: { message: 'read boom' } })
                const hit = rows.filter(r => f.every(([k, val]) => r[k] === val))
                return Promise.resolve({ data: hit[0] ?? null, error: null })
              } } : q
            },
          }
          return q as never
        },
        delete() {
          return {
            lt(c: string, v: string) {
              calls.push(`delete ${c}<`)
              if (opts.failDelete) return Promise.resolve({ error: { message: 'delete boom' } })
              for (let i = rows.length - 1; i >= 0; i--) if (String(rows[i][c]) < v) rows.splice(i, 1)
              return Promise.resolve({ error: null })
            },
          }
        },
        upsert(row: Record<string, unknown>, o: { onConflict: string }) {
          calls.push(`upsert ${o.onConflict}`)
          if (opts.failWrite) return Promise.resolve({ error: { message: 'write boom' } })
          const keys = o.onConflict.split(',')
          const i = rows.findIndex(r => keys.every(k => r[k] === row[k]))
          if (i >= 0) rows[i] = { ...rows[i], ...row }
          else rows.push({ ...row })
          return Promise.resolve({ error: null })
        },
      }
    },
  }
  return { db, rows, calls }
}

const ctx = scrubContext({ targetURL: 'https://example.com', endpoints: [{ url: 'https://example.com/login', method: 'POST', formFields: ['email'] }] })
const A = '00000000-0000-4000-8000-00000000000a'
const B = '00000000-0000-4000-8000-00000000000b'

Deno.test('userCrawlKey is sha256, per account and per crawl', async () => {
  const ka = await userCrawlKey(A, ctx)
  assert(/^[0-9a-f]{64}$/.test(ka))
  assertEquals(await userCrawlKey(A, ctx), ka)
  assertFalse(ka === await userCrawlKey(B, ctx))
  const other = scrubContext({ targetURL: 'https://example.com', endpoints: [{ url: 'https://example.com/signup', method: 'POST' }] })
  assertFalse(ka === await userCrawlKey(A, other))
  await assertRejects(() => userCrawlKey('', ctx))
})

Deno.test('expiryCutoff and isExpired use 24 hours', () => {
  const now = Date.parse('2026-11-26T14:00:00Z')
  assertEquals(expiryCutoff(now), '2026-11-25T14:00:00.000Z')
  assertEquals(TEMPLATE_CACHE_TTL_MS, 86_400_000)
  assertFalse(isExpired('2026-11-26T13:00:00Z', now))
  assertFalse(isExpired('2026-11-25T14:00:00Z', now))
  assert(isExpired('2026-11-25T13:59:59Z', now))
  assert(isExpired(null, now))
  assert(isExpired('not a date', now))
})

Deno.test('purgeExpiredTemplates deletes rows older than 24h only', async () => {
  const { db, rows } = fakeDb()
  const now = Date.parse('2026-11-26T14:00:00Z')
  rows.push({ created_by: A, crawl_hash: 'old', created_at: '2026-11-25T10:00:00.000Z' })
  rows.push({ created_by: B, crawl_hash: 'new', created_at: '2026-11-26T10:00:00.000Z' })
  assert(await purgeExpiredTemplates(db, now))
  assertEquals(rows.map(r => r.crawl_hash), ['new'])
  await quiet(async () => assertFalse(await purgeExpiredTemplates(fakeDb({ failDelete: true }).db, now)))
})

Deno.test('getCachedTemplates only returns the same account\'s live row', async () => {
  const { db, rows, calls } = fakeDb()
  const now = Date.now()
  const key = await userCrawlKey(A, ctx)
  rows.push({ created_by: A, crawl_hash: key, templates: ['id: t'], rationale: 'r', created_at: new Date(now - 1000).toISOString() })
  assertEquals(await getCachedTemplates(db, A, key, now), { templates: ['id: t'], rationale: 'r' })
  assert(calls.includes('select created_by,crawl_hash'))
  assertEquals(await getCachedTemplates(db, B, key, now), null)
  assertEquals(await getCachedTemplates(db, A, key, now + TEMPLATE_CACHE_TTL_MS + 5000), null)
  rows[0].templates = 'not a list'
  assertEquals(await getCachedTemplates(db, A, key, now), null)
  await quiet(async () => assertEquals(await getCachedTemplates(fakeDb({ failRead: true }).db, A, key, now), null))
})

Deno.test('saveCachedTemplates upserts on (created_by, crawl_hash) with owner and fresh created_at', async () => {
  const { db, rows, calls } = fakeDb()
  const key = await userCrawlKey(A, ctx)
  assert(await saveCachedTemplates(db, A, key, { templates: ['id: 1'], rationale: 'x' }))
  assert(await saveCachedTemplates(db, A, key, { templates: ['id: 2'], rationale: 'y' }))
  assert(await saveCachedTemplates(db, B, key, { templates: ['id: b'], rationale: '' }))
  assertEquals(rows.length, 2)
  assertEquals(rows.find(r => r.created_by === A)?.templates, ['id: 2'])
  assert(calls.includes('upsert created_by,crawl_hash'))
  assert(Math.abs(Date.parse(String(rows[0].created_at)) - Date.now()) < 5000)
  await quiet(async () => assertFalse(await saveCachedTemplates(fakeDb({ failWrite: true }).db, A, key, { templates: [], rationale: '' })))
})
