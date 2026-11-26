// deno test supabase/functions/_shared/cache_sanitize.test.ts
import { assert, assertEquals, assertFalse } from 'jsr:@std/assert@1'
import { checkSharedExplanation, findUserSpecificContent, genericLabel } from './cache_sanitize.ts'

const clean = {
  simply: 'Untrusted input is written straight into the page, so an attacker can run scripts in your users\' browsers. See https://owasp.org/www-community/attacks/xss/ for background.',
  actions: [
    'Escape user input before rendering it, or use your template engine\'s auto-escaping.',
    'Add a Content-Security-Policy header.',
    'Return a generic error page (without stack traces) to users.',
    'Run `npm audit fix` and redeploy.',
    'Never commit .env files; add .env to .gitignore.',
    'Block requests to 169.254.169.254 from your app.',
  ],
}

Deno.test('a generic explanation passes', () => {
  assertEquals(checkSharedExplanation(clean), { ok: true, reasons: [] })
})

Deno.test('paths are rejected', () => {
  for (const t of ['Look in src/routes/admin.ts', 'Edit /Users/zeph/Desktop/Trojan/app.js', 'See C:\\code\\app\\x.cs', 'open ~/projects/acme/.env']) {
    assertFalse(checkSharedExplanation({ simply: t, actions: [] }).ok, t)
  }
})

Deno.test('code is rejected', () => {
  for (const t of ['```js\nres.send(x)\n```', 'const q = `SELECT * FROM users WHERE id=${id}`;', '`' + 'a'.repeat(70) + '`', 'app.get("/x", (req, res) => {']) {
    assertFalse(checkSharedExplanation({ simply: 'ok', actions: [t] }).ok, t)
  }
})

Deno.test('secrets are rejected (patterns built at runtime so this file holds no key-shaped literals)', () => {
  const samples = [
    'AKIA' + 'ABCDEFGHIJKLMNOP',
    'ghp_' + 'a1B2c3D4e5F6g7H8i9J0k1L2m3N4',
    'sk_' + 'live_' + 'abcdefgh12345678',
    'xox' + 'b-' + '1234567890-abcdefghij',
    '-----BEGIN ' + 'RSA PRIVATE KEY-----',
    'eyJ' + 'hbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJl',
    'postgres://admin:' + 'hunter2@db.internal:5432/app',
    'Zq8Lm3Vt9Rk2Wp7Xn4Bc6Hd1Jf5Gs0Ty' + 'Ua3Ek9',
  ]
  for (const s of samples) {
    const r = checkSharedExplanation({ simply: `Value ${s} found`, actions: [] })
    assertFalse(r.ok, s.slice(0, 6))
    assert(r.reasons.some((x) => x.startsWith('secret:')), s.slice(0, 6))
  }
})

Deno.test('non-doc URLs, emails and public IPs are rejected', () => {
  assertFalse(checkSharedExplanation({ simply: 'Your site https://shop.acmepets.ca/admin is open', actions: [] }).ok)
  assertFalse(checkSharedExplanation({ simply: 'Email zeph@acmepets.ca', actions: [] }).ok)
  assertFalse(checkSharedExplanation({ simply: 'Server 52.14.88.3 is exposed', actions: [] }).ok)
})

Deno.test('echoes of this request\'s own values are rejected', () => {
  const user = {
    filePath: 'lib/payments/stripeHooks.rb',
    codeSnippet: 'Stripe::Webhook.construct_event(payload, sig, nil)',
    aboutYou: 'I run a tiny dog grooming business in Halifax and hate jargon',
    rawMessage: 'Webhook signature secret is nil in construct_event call for payments handler',
  }
  const r = (simply: string) => checkSharedExplanation({ simply, actions: [] }, user)
  assertEquals(r('Generic webhook advice.').ok, true)
  assertEquals(r('Your stripeHooks.rb file is the culprit').reasons, ['echo:file_name'])
  assert(r('stripe::webhook.construct_event(payload, sig, nil) is unsafe').reasons.includes('echo:snippet'))
  assert(r('Since you run a tiny dog grooming business this matters').reasons.includes('echo:about_you'))
  assert(r('The webhook signature secret is nil in construct_event call here').reasons.includes('echo:scanner_message'))
  // Common file names are not treated as an echo.
  assertEquals(checkSharedExplanation({ simply: 'Update the version in package.json', actions: [] }, { filePath: 'package.json' }).ok, true)
  assertEquals(checkSharedExplanation({ simply: 'Update package.json', actions: [] }, { filePath: 'apps/acme-web/package.json' }).ok, true)
})

Deno.test('client redaction labels never enter the shared cache', () => {
  const r = checkSharedExplanation({ simply: 'Rotate <SECRET: aws-access-token, 20, AKIA, 3.7> now', actions: [] })
  assertFalse(r.ok)
  assert(r.reasons.includes('secret:redaction_label'))
})

Deno.test('shape and size limits', () => {
  assertFalse(checkSharedExplanation({ simply: 5 as unknown as string, actions: [] }).ok)
  assertFalse(checkSharedExplanation({ simply: 'x'.repeat(2001), actions: [] }).ok)
  assertFalse(checkSharedExplanation({ simply: 'x', actions: Array(13).fill('a') }).ok)
})

Deno.test('genericLabel keeps rule titles and drops anything user-shaped', () => {
  assertEquals(genericLabel('Leaked AWS Access Token'), 'Leaked AWS Access Token')
  assertEquals(genericLabel('CVE-2024-1234 in lodash'), 'CVE-2024-1234 in lodash')
  assertEquals(genericLabel('SSRF/open redirect'), 'SSRF/open redirect')
  assertEquals(genericLabel("Tainted 'req.query.x'"), '')
  assertEquals(genericLabel('Issue in src/app.ts'), '')
  assertEquals(genericLabel('See https://acme.test/x'), '')
  assertEquals(genericLabel('x'.repeat(121)), '')
  assertEquals(genericLabel(undefined), '')
  assertEquals(findUserSpecificContent('Use HTTPS everywhere.'), [])
})
