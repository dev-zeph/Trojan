import { assertEquals } from 'jsr:@std/assert@1'
import { chunk, groupByEcosystem, normalizePypi, parseRequest, rowMatchesWanted, MAX_PACKAGES } from './lib.ts'

Deno.test('normalizePypi follows PEP 503', () => {
  assertEquals(normalizePypi('Foo_Bar.baz--Qux'), 'foo-bar-baz-qux')
})

Deno.test('parseRequest normalizes ecosystem and pypi names', () => {
  const r = parseRequest({ packages: [
    { ecosystem: 'NPM', name: 'next', version: '14.1.0' },
    { ecosystem: 'PyPI', name: 'Django_REST.framework' },
  ] })
  assertEquals(r.ok, true)
  if (r.ok) {
    assertEquals(r.value.packages[0].ecosystem, 'npm')
    assertEquals(r.value.packages[1].name, 'django-rest-framework')
    assertEquals(r.value.since, null)
  }
})

Deno.test('parseRequest rejects bad input', () => {
  assertEquals(parseRequest(null).ok, false)
  assertEquals(parseRequest({}).ok, false)
  assertEquals(parseRequest({ packages: [{ ecosystem: 'pip', name: 'x' }] }).ok, false)
  assertEquals(parseRequest({ packages: [{ ecosystem: 'npm', name: '' }] }).ok, false)
  assertEquals(parseRequest({ packages: [{ ecosystem: 'npm', name: 'x', version: 1 }] }).ok, false)
  assertEquals(parseRequest({ packages: [], since: 'nope' }).ok, false)
  const big = Array.from({ length: MAX_PACKAGES + 1 }, () => ({ ecosystem: 'npm', name: 'x' }))
  assertEquals(parseRequest({ packages: big }).ok, false)
})

Deno.test('parseRequest accepts empty list and valid since', () => {
  const r = parseRequest({ packages: [], since: '2026-01-01T00:00:00Z' })
  assertEquals(r.ok, true)
  if (r.ok) assertEquals(r.value.since, '2026-01-01T00:00:00.000Z')
})

Deno.test('groupByEcosystem dedupes', () => {
  const g = groupByEcosystem([
    { ecosystem: 'npm', name: 'a' }, { ecosystem: 'npm', name: 'a' },
    { ecosystem: 'npm', name: 'b' }, { ecosystem: 'go', name: 'a' },
  ])
  assertEquals(g.get('npm'), ['a', 'b'])
  assertEquals(g.get('go'), ['a'])
})

Deno.test('chunk splits', () => {
  assertEquals(chunk([1, 2, 3, 4, 5], 2), [[1, 2], [3, 4], [5]])
  assertEquals(chunk([], 2), [])
})

Deno.test('rowMatchesWanted normalizes stored pypi names', () => {
  const wanted = new Map([['pypi', ['django-rest-framework']], ['npm', ['next']]])
  assertEquals(rowMatchesWanted({ ecosystem: 'pypi', package: 'Django_REST.framework' }, wanted), true)
  assertEquals(rowMatchesWanted({ ecosystem: 'npm', package: 'Next' }, wanted), false)
  assertEquals(rowMatchesWanted({ ecosystem: 'go', package: 'next' }, wanted), false)
})
