import { assert, assertEquals, assertFalse } from 'jsr:@std/assert@1'
import { canonicalCrawl, crawlKey, looksLikeToken, scrubContext, scrubNames, scrubSegment, scrubUrl } from './crawl_scrub.ts'

// Fake values built at run time (same shapes as crawl_scrub_test.go).
const TOK = 'Qz7'.repeat(11) + 'k'
const HEX = 'c0ffee'.repeat(6)
const JWT = 'eyJ' + 'hb9'.repeat(6) + '.' + 'eyJ' + 'pl4'.repeat(6) + '.' + 'sg2'.repeat(8)
const expand = (s: string) => s.replaceAll('<TOK>', TOK).replaceAll('<HEX>', HEX).replaceAll('<JWT>', JWT)

const vectorsPath = new URL('../../../internal/dast/testdata/crawl_scrub_vectors.json', import.meta.url)
const vectors = JSON.parse(expand(await Deno.readTextFile(vectorsPath)))

Deno.test('scrubUrl matches the shared vectors', () => {
  for (const c of vectors.urls) assertEquals(scrubUrl(c.in), c.out, c.in)
})

Deno.test('scrubUrl never keeps fake values, passwords or fragments', () => {
  for (const c of vectors.urls) {
    const got = scrubUrl(c.in)
    for (const v of [TOK, HEX, JWT, 'Pw', 'frag']) assertFalse(got.includes(v), `${c.in} kept ${v}`)
  }
})

Deno.test('scrubUrl rejects non-strings', () => {
  assertEquals(scrubUrl(undefined), '')
  assertEquals(scrubUrl(42), '')
  assertEquals(scrubUrl({ url: 'https://example.com' }), '')
})

Deno.test('scrubSegment', () => {
  const cases: Record<string, string> = {
    '123': '123', 'orders': 'orders', 'v2': 'v2', '': '',
    '550e8400-e29b-41d4-a716-446655440000': '{uuid}',
    '1234567890': '{num}', '123456789': '123456789',
    [TOK]: '{token}', [HEX]: '{token}', [JWT]: '{token}',
    'how-to-reset-password-2024': 'how-to-reset-password-2024',
    'a1b2c3d4e5f6g7': '{token}',
  }
  for (const [k, v] of Object.entries(cases)) assertEquals(scrubSegment(k), v, k)
})

Deno.test('looksLikeToken', () => {
  for (const s of [TOK, HEX, JWT, 'a'.repeat(40), 'abc%2Fdef%3Dxyz', 'word'.repeat(6)]) assert(looksLikeToken(s), s)
  for (const s of ['login', 'account-settings', 'v1', '2024', 'my_profile', 'index.html', 'terms-of-service']) assertFalse(looksLikeToken(s), s)
})

Deno.test('scrubNames cleans, dedupes, sorts and caps', () => {
  assertEquals(scrubNames(['b', 'a', 'a', ' c ', '', 'bad name', TOK, 'n'.repeat(65), 'user[email]', 7]), ['a', 'b', 'c', 'user[email]'])
  assertEquals(scrubNames('not a list'), [])
  const many = Array.from({ length: 80 }, (_, i) => 'f' + 'x'.repeat(i % 40) + String.fromCharCode(97 + (i % 26)))
  assert(scrubNames(many).length <= 50)
})

Deno.test('scrubContext matches the shared request vector and key', async () => {
  const got = scrubContext(vectors.request.in)
  assertEquals(got, vectors.request.out)
  assertEquals(await crawlKey(got), vectors.request.digest)
  const text = JSON.stringify(got) + canonicalCrawl(got)
  for (const s of [TOK, HEX, 'me:pw', '/account', '/cart']) assertFalse(text.includes(s), s)
})

Deno.test('scrubContext survives malformed bodies', () => {
  for (const body of [null, undefined, 'x', 1, [], { endpoints: 'x' }, { endpoints: [null, 1, { url: 5 }] }]) {
    const c = scrubContext(body)
    assertEquals(c.endpoints, [])
    assertEquals(c.targetURL, '')
    assertEquals(c.maxTemplates, 10)
  }
  assertEquals(scrubContext({ maxTemplates: 3 }).maxTemplates, 3)
  assertEquals(scrubContext({ maxTemplates: 3.5 }).maxTemplates, 10)
})

Deno.test('scrubContext caps endpoints at 200', () => {
  const endpoints = Array.from({ length: 500 }, (_, i) => ({ url: `https://example.com/p${'x'.repeat(i % 50)}/${String.fromCharCode(97 + (i % 26))}`, method: 'GET' }))
  assert(scrubContext({ endpoints }).endpoints.length <= 200)
})

Deno.test('crawlKey ignores query values and changes with the prompt', async () => {
  const base = { targetURL: 'https://example.com/?a=1', endpoints: [{ url: `https://example.com/login?sid=${HEX}`, method: 'GET', queryParams: ['sid'] }], techHints: ['react'] }
  const k = await crawlKey(scrubContext(base))
  assert(/^[0-9a-f]{64}$/.test(k))
  const same = { ...base, targetURL: 'https://u:p@example.com/?a=2#x', endpoints: [{ url: `https://example.com/login?sid=${TOK}`, method: 'get', queryParams: ['sid'] }] }
  assertEquals(await crawlKey(scrubContext(same)), k)
  for (const changed of [
    { ...base, endpoints: [{ url: 'https://example.com/signin', method: 'GET' }] },
    { ...base, targetURL: 'https://other.example.com' },
    { ...base, techHints: ['django'] },
    { ...base, maxTemplates: 3 },
  ]) assertFalse((await crawlKey(scrubContext(changed))) === k)
})
