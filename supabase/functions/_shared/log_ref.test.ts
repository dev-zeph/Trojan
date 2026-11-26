import { assertEquals, assertFalse } from 'jsr:@std/assert@1'
import { logRef } from './log_ref.ts'

Deno.test('logRef is 12 hex chars, stable, and never the id', async () => {
  const id = crypto.randomUUID()
  const a = await logRef(id)
  assertEquals(a.length, 12)
  assertEquals(/^[0-9a-f]{12}$/.test(a), true)
  assertEquals(await logRef(id), a)
  assertFalse(a === (await logRef(crypto.randomUUID())))
  assertFalse(id.replaceAll('-', '').includes(a))
})

Deno.test('logRef matches the synthesize derivation', async () => {
  const id = '00000000-0000-4000-8000-000000000001'
  const d = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(`synthesize-log:${id}`))
  const want = Array.from(new Uint8Array(d).slice(0, 6), (b) => b.toString(16).padStart(2, '0')).join('')
  assertEquals(await logRef(id), want)
})
