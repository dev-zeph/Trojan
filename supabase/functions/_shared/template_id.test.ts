import { assertEquals, assert, assertFalse } from 'jsr:@std/assert@1'
import { setTemplateId, setTemplateIds } from './template_id.ts'

Deno.test('setTemplateId replaces only the top-level id', () => {
  const t = 'id: alphapets-loyalty-api-idor\ninfo:\n  name: Alpha Pets loyalty API\n  metadata:\n    id: nested\nhttp: []\n'
  const out = setTemplateId(t, 7)
  assert(out.startsWith('id: trojan-custom-007\n'))
  assertFalse(out.includes('alphapets'))
  assert(out.includes('    id: nested'))
})

Deno.test('setTemplateId adds an id when there is none, and handles quoted ids', () => {
  assertEquals(setTemplateId('info: {}\n', 12), 'id: trojan-custom-012\ninfo: {}\n')
  assertEquals(setTemplateId('# c\nid: "x-y"\ninfo: {}\n', 1), '# c\nid: trojan-custom-001\ninfo: {}\n')
  assertEquals(setTemplateId('id: a\n', 1234), 'id: trojan-custom-1234\n')
})

Deno.test('setTemplateIds numbers in order from 001', () => {
  assertEquals(setTemplateIds(['id: a\n', 'id: b\n']), ['id: trojan-custom-001\n', 'id: trojan-custom-002\n'])
  assertEquals(setTemplateIds([]), [])
})
