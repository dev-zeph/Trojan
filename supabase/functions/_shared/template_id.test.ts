import { assertEquals, assert, assertFalse } from 'jsr:@std/assert@1'
import { isFlowStyleTemplate, setTemplateId, setTemplateIds } from './template_id.ts'

const topLevelIds = (t: string) => t.match(/^\uFEFF?(?:"id"|'id'|id)[ \t]*:.*$/gm) ?? []

Deno.test('setTemplateId replaces only the top-level id', () => {
  const t = 'id: alphapets-loyalty-api-idor\ninfo:\n  name: Alpha Pets loyalty API\n  metadata:\n    id: nested\nhttp: []\n'
  const out = setTemplateId(t, 7)!
  assert(out.startsWith('id: trojan-custom-007\n'))
  assertFalse(out.includes('alphapets'))
  assert(out.includes('    id: nested'))
})

Deno.test('setTemplateId adds an id when there is none, and handles quoted ids', () => {
  assertEquals(setTemplateId('info: {}\n', 12), 'id: trojan-custom-012\ninfo: {}\n')
  assertEquals(setTemplateId('# c\nid: "x-y"\ninfo: {}\n', 1), '# c\nid: trojan-custom-001\ninfo: {}\n')
  assertEquals(setTemplateId('id: a\n', 1234), 'id: trojan-custom-1234\n')
})

// The UX Lead's round 3 edge cases (R3-P3-1).
Deno.test('setTemplateId handles quoted keys, space before the colon, a BOM and repeats', () => {
  const cases: Record<string, string> = {
    quotedKey: '"id": alphapets-x\ninfo: {}\n',
    singleQuotedKey: "'id': alphapets-x\ninfo: {}\n",
    spaceBeforeColon: 'id : alphapets-x\ninfo: {}\n',
    tabBeforeColon: 'id\t: alphapets-x\ninfo: {}\n',
    bom: '\uFEFFid: alphapets-x\ninfo: {}\n',
    bomQuoted: '\uFEFF"id" : alphapets-x\ninfo: {}\n',
    lastLineNoNewline: 'info: {}\nid: alphapets-x',
    crlf: 'id: alphapets-x\r\ninfo: {}\r\n',
    duplicateIds: 'id: alphapets-x\ninfo: {}\nid: alphapets-y\n',
    docMarker: '---\nid: alphapets-x\ninfo: {}\n',
  }
  for (const [name, input] of Object.entries(cases)) {
    const out = setTemplateId(input, 3)
    assert(out !== null, `${name}: rejected`)
    assertFalse(out.includes('alphapets'), `${name}: ${out}`)
    assertEquals(topLevelIds(out), ['id: trojan-custom-003'], name)
    assertFalse(out.startsWith('\uFEFF'), `${name}: BOM kept`)
  }
  assertEquals(setTemplateId('---\ninfo: {}\n', 2), '---\nid: trojan-custom-002\ninfo: {}\n')
  assertEquals(setTemplateId('idx: 1\nid_extra: 2\n', 1), 'id: trojan-custom-001\nidx: 1\nid_extra: 2\n')
})

Deno.test('setTemplateId rejects flow-style templates', () => {
  for (const t of ['{id: alphapets-x}', '# c\n{id: alphapets-x, info: {name: y}}\n', '  {"id": "alphapets-x"}']) {
    assertEquals(setTemplateId(t, 1), null, t)
  }
})

Deno.test('isFlowStyleTemplate looks at the first real line only', () => {
  assert(isFlowStyleTemplate('{id: x}'))
  assert(isFlowStyleTemplate('\n# comment\n---\n{id: x}'))
  assertFalse(isFlowStyleTemplate('id: x\ninfo: {name: y}\n'))
  assertFalse(isFlowStyleTemplate(''))
})

Deno.test('setTemplateIds numbers in order from 001', () => {
  assertEquals(setTemplateIds(['id: a\n', 'id: b\n']), ['id: trojan-custom-001\n', 'id: trojan-custom-002\n'])
  assertEquals(setTemplateIds([]), [])
})

Deno.test('setTemplateIds drops flow-style templates and numbers the rest without gaps', () => {
  assertEquals(
    setTemplateIds(['id: a\n', '{id: acme-flow}', '"id": b\n']),
    ['id: trojan-custom-001\n', 'id: trojan-custom-002\n'],
  )
})
