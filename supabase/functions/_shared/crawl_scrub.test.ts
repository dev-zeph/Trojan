import { assert, assertEquals, assertFalse } from 'jsr:@std/assert@1'
import {
  canonicalCrawl, charClass, crawlKey, hasUnsafeChar, isPersonParent, looksLikeEmail, looksLikePersonName, looksLikeToken,
  randomLetters, scrubContext, scrubNames, scrubPath, scrubSegment, scrubUrl, shortMixedToken,
} from './crawl_scrub.ts'

// Fake values built at run time (same shapes as crawl_scrub_test.go).
const TOK = 'Qz7'.repeat(11) + 'k'
const HEX = 'c0ffee'.repeat(6)
const JWT = 'eyJ' + 'hb9'.repeat(6) + '.' + 'eyJ' + 'pl4'.repeat(6) + '.' + 'sg2'.repeat(8)
const LET20 = 'hQkZpLmWtR'.repeat(2)
const LOW16 = 'qwhzk'.repeat(3) + 'x'
const MIX11 = 'aB3' + 'dE6' + 'gH9' + 'jK'
const DIG10 = 'a1' + 'b2' + 'c3' + 'd4' + 'e5'
const expand = (s: string) => s.replaceAll('<TOK>', TOK).replaceAll('<HEX>', HEX).replaceAll('<JWT>', JWT)
  .replaceAll('<LET20>', LET20).replaceAll('<LOW16>', LOW16).replaceAll('<MIX11>', MIX11).replaceAll('<DIG10>', DIG10)

const vectorsPath = new URL('../../../internal/dast/testdata/crawl_scrub_vectors.json', import.meta.url)
const vectors = JSON.parse(expand(await Deno.readTextFile(vectorsPath)))

Deno.test('scrubUrl matches the shared vectors', () => {
  for (const c of vectors.urls) assertEquals(scrubUrl(c.in), c.out, c.in)
})

Deno.test('scrubUrl never keeps fake values, passwords or fragments', () => {
  for (const c of vectors.urls) {
    const got = scrubUrl(c.in)
    for (const v of [TOK, HEX, JWT, LET20, LOW16, MIX11, DIG10, 'Pw', 'frag', 'jane', 'zephaniah', '@']) assertFalse(got.includes(v), `${c.in} kept ${v}`)
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

Deno.test('looksLikeEmail', () => {
  for (const s of ['jane.doe@example.com', 'jane+news@example.com', 'jane@example', '@janedoe']) assert(looksLikeEmail(s), s)
  for (const s of ['jane.doe', 'orders', 'example.com', '']) assertFalse(looksLikeEmail(s), s)
})

Deno.test('isPersonParent', () => {
  for (const s of ['users', 'U', 'profile', 'Members', 'authors', 'customers']) assert(isPersonParent(s), s)
  for (const s of ['orders', 'docs', 'contact', 'account', '']) assertFalse(isPersonParent(s), s)
})

Deno.test('looksLikePersonName', () => {
  for (const s of ['zephaniah-chizulu', 'Jane_Doe', 'jdoe', 'acme-corp']) assert(looksLikePersonName(s), s)
  for (const s of ['123', '{uuid}', 'new', 'me', 'Settings', 'sign-in', '']) assertFalse(looksLikePersonName(s), s)
})

Deno.test('scrubPath', () => {
  assertEquals(scrubPath(['', 'users', 'jane-doe', 'orders']), ['users', '{name}', 'orders'])
  assertEquals(scrubPath(['users', '123', 'orders']), ['users', '123', 'orders'])
  assertEquals(scrubPath(['users', 'new']), ['users', 'new'])
  assertEquals(scrubPath(['u', 'jane@example.com']), ['u', '{email}'])
  assertEquals(scrubPath(['p;jsessionid=x', '.', '..', 'x']), ['p', 'x'])
  assertEquals(scrubPath(['docs', 'getting-started']), ['docs', 'getting-started'])
  assertEquals(scrubPath(['users', TOK]), ['users', '{token}'])
})

Deno.test('randomLetters', () => {
  for (const s of [LET20, LOW16, 'ZxCv' + 'BnMq' + 'WeRtYuIoPa']) assert(randomLetters(s), s)
  for (const s of ['internationalization', 'getUserProfileSettings', 'troubleshootingguide', 'dashboard', 'gettingstarted', 'Supercalifragilistic', LET20.slice(0, 15), 'abc123defghijklmnop']) assertFalse(randomLetters(s), s)
})

Deno.test('shortMixedToken', () => {
  for (const s of [MIX11, DIG10, 'Z9y8X7w6']) assert(shortMixedToken(s), s)
  for (const s of ['iPhone15Pro', 'abc123def', 'v2', 'dashboard', 'a1-b2-c3-d4', 'release2024', 'aB3dE6g', 'a1'.repeat(6)]) assertFalse(shortMixedToken(s), s)
})

Deno.test('hasUnsafeChar and charClass', () => {
  for (const s of ['https://a.example\\@b/x', 'https://a.example/x\ty', 'https://a.example/\n', 'x\x7f']) assert(hasUnsafeChar(s), s)
  assertFalse(hasUnsafeChar('https://a.example/caf\u00e9?q=1'))
  assertEquals([charClass('a'), charClass('Z'), charClass('7'), charClass('-'), charClass('\u00e9')], [0, 1, 2, 3, 3])
})
