// deno test supabase/functions/_shared/cache_sanitize.test.ts
import { assert, assertEquals, assertFalse } from 'jsr:@std/assert@1'
import {
  aboutYouEchoed, checkSharedExplanation, findBareHosts, findUserSpecificContent, genericLabel, hasSendOrVisitInstruction,
  requestHosts,
} from './cache_sanitize.ts'

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

// Fake hosts, built at runtime from a random label: no real customer data.
const fakeLabel = () => 'fx' + crypto.randomUUID().replace(/-/g, '').slice(0, 10)

Deno.test('bare host names are rejected; product names and docs hosts are not', () => {
  const host = `shop.${fakeLabel()}.ca`
  for (const t of [`Your site ${host} is exposed`, `Check ${host.toUpperCase().replace(/\.CA$/, '.ca')}.`, `admin.${fakeLabel()}.com:8443 answers`]) {
    const r = checkSharedExplanation({ simply: t, actions: [] })
    assertFalse(r.ok, t)
    assert(r.reasons.includes('host:bare'), t)
  }
  for (const t of [
    'Upgrade ASP.NET and Socket.IO; Socket.io too.',
    'Edit settings.py, next.config.js, package.json and README.md.',
    'Node.js, Vue.js and Chart.js apps are affected, e.g. older versions like v1.2.3.',
    'See owasp.org, cwe.mitre.org and docs.github.com for details; use example.com in docs.',
    'Rotate keys at the provider. Then redeploy.App owners should check logs.',
  ]) {
    assertEquals(checkSharedExplanation({ simply: t, actions: [] }).reasons.filter((x) => x.startsWith('host')), [], t)
  }
})

Deno.test("the request's own target host is rejected in any form", () => {
  const host = `www.${fakeLabel()}.store`
  const bare = host.slice(4)
  const user = { filePath: `https://${host}:8443/login?next=/admin` }
  assertEquals(requestHosts(user).sort(), [bare, host].sort())
  const r = checkSharedExplanation({ simply: `Attackers can reach ${bare.toUpperCase()} directly`, actions: [] }, user)
  assertFalse(r.ok)
  assert(r.reasons.includes('echo:target_host'))
  // Host given as a bare file path (website findings without a scheme) and inside the scanner message.
  const h2 = `api.${fakeLabel()}.io`
  assertEquals(requestHosts({ filePath: h2 }), [h2])
  assertEquals(requestHosts({ filePath: 'package.json' }), [])
  assertEquals(requestHosts({ filePath: 'app/settings.py' }), [])
  assert(requestHosts({ rawMessage: `GET http://user@${h2}:80/x returned 500` }).includes(h2))
  // A different host in the text is still caught by the general check, not the echo.
  assertEquals(checkSharedExplanation({ simply: 'Generic advice.', actions: [] }, user), { ok: true, reasons: [] })
})

Deno.test('findBareHosts lists hosts once, lower-cased, skipping emails and URLs handled elsewhere', () => {
  const h = `${fakeLabel()}.dev`
  assertEquals(findBareHosts(`${h} and ${h.toUpperCase().replace(/\.DEV$/, '.dev')} and ops@${fakeLabel()}.com`), [h])
})

// ---------------------------------------------------------------------------
// UX Lead probe set (2026-11-26, probe.ts): 46 pattern cases and 6 echo cases.
// Secrets and hosts are generated at runtime, so this file holds no key-shaped
// literals. Each case is [name, text, expected ok].
// ---------------------------------------------------------------------------
const rnd = (n: number, abc: string) => {
  const bytes = crypto.getRandomValues(new Uint8Array(n))
  return Array.from(bytes, (b) => abc[b % abc.length]).join('')
}
const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
const HEX = '0123456789abcdef'
// Random base64 can, rarely, come out without one of the character classes; force all three.
const b64 = (n: number) => 'aZ9' + rnd(n - 3, B64)
const hex = (n: number) => 'a1' + rnd(n - 2, HEX)

function probeCases(): Array<[string, string, boolean]> {
  const shop = fakeLabel()
  return [
    ['bare hostname', `Your site shop.${shop}.ca is exposing its admin panel.`, false],
    ['hostname w/ port', `Check staging.${shop}.com:8443 for the open endpoint.`, false],
    ['localhost url', 'Visit http://localhost:3000/admin to confirm.', false],
    ['docs url', 'See https://owasp.org/www-community/attacks/xss/ for more.', true],
    ['github.com user repo url', `See https://github.com/alice-${shop}/private-billing/blob/main/x for more.`, false],
    ['example.com subdomain', `Visit https://${shop}.example.com/admin`, false],
    ['win path backslash', `Open C:\\Users\\alice\\${shop}\\config.ts and remove the key.`, false],
    ['win path fwd slash no ext', `Open C:/Users/alice/${shop} and remove the key.`, false],
    ['win path after colon', 'File:C:\\Users\\alice\\key', false],
    ['UNC path', `It is stored on \\\\fileserver\\${shop}-share\\secrets`, false],
    ['~/ path', 'Delete ~/.aws/credentials after rotating.', false],
    ['~ path no slash prefix', `Look in(~/${shop}/app) now`, false],
    ['abs path lowercase users', `Edit /users/alice/${shop}/config now`, false],
    ['abs path /app (docker) no ext', 'Edit /app/src/payments-settings now', false],
    ['abs path /workspace no ext', `Edit /workspace/${shop}-billing/server now`, false],
    ['abs path /Users w/ ext', `Edit /Users/alice/${shop}/config.ts now`, false],
    ['rel path no ext', 'Look in src/payments-settings and fix it.', false],
    ['rel path w/ ext', 'Look in src/payments-settings.ts and fix it.', false],
    ['bare filename w/ ext', 'Open payments-settings.ts and fix it.', false],
    ['dotenv var', 'Set STRIPE_SECRET_KEY in your .env file.', true],
    ['short inline code', 'Replace `db.query("SELECT * FROM orders WHERE id=" + id)` with a parameterised query.', false],
    ['short code no backticks', 'Change res.send(req.query.name) to escape output.', false],
    ['js assignment one-liner', 'const apiKey = process.env.KEY', false],
    ['python assignment', 'api_key = os.environ["ACME_KEY"]', false],
    ['SQL lowercase', 'select * from orders where id = 1', false],
    ['code line w/ semicolon', 'Change the line to: el.innerHTML = name;', false],
    ['base64 secret 32', 'The key ' + b64(32) + ' is exposed.', false],
    ['base64 secret 24', 'The key ' + b64(24) + ' is exposed.', false],
    ['base64 40 w/ padding', 'Token: ' + b64(38) + '==', false],
    ['hex secret 40', 'The token ' + hex(40) + ' is exposed.', false],
    ['hex secret 64', 'The token ' + hex(64) + ' is exposed.', false],
    ['git commit sha', 'Found in commit ' + hex(40) + '.', false],
    ['password literal', 'The password ' + 'hunter' + '2 is in the code.', false],
    ['aws key', 'AK' + 'IA' + rnd(16, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'), false],
    ['aws secret 40', 'secret ' + b64(40).replace(/\+/g, 'q'), false],
    ['openai sk-proj', 'sk-' + 'proj-' + b64(40).replace(/[+/]/g, 'x'), false],
    ['email', `Contact alice@${shop}.ca`, false],
    ['public ip', 'The server 203.0.113.7 is open.', false],
    ['private 172.16 ip', 'The server 172.16.4.2 is open.', false],
    ['10.x ip', 'The server 10.1.2.3 is open.', false],
    ['ipv6', 'The server 2001:db8:85a3::8a2e:370:7334 is open.', false],
    ['package name', `Upgrade @${shop}-internal/billing-sdk to 2.3.1.`, false],
    ['redaction label', 'The <SECRET: type=aws> is exposed', false],
    ['phone', 'Call 902-555-0199 to report.', false],
    // Known limits of a content-only check: free text that names nobody we can
    // recognise. These are covered by the echo checks on write (below) and by the
    // prompt, which never sees the user's text.
    ['email obfuscated (limit)', `Contact alice at ${shop} dot ca`, true],
    ['company name (limit)', 'Alpha Pet Supplies stores card numbers in plain text.', true],
  ]
}

Deno.test('UX probe set: 46 pattern cases', () => {
  const cases = probeCases()
  assertEquals(cases.length, 46)
  const wrong = cases.filter(([, t, ok]) => checkSharedExplanation({ simply: t, actions: ['Rotate the key.'] }).ok !== ok)
  assertEquals(wrong.map(([n]) => n), [])
})

Deno.test('UX probe set: echo cases', () => {
  const cases: Array<[string, string, Record<string, string>, boolean]> = [
    ['aboutYou short company 3 words', 'Alpha Pet Supplies stores cards insecurely.', { aboutYou: 'Alpha Pet Supplies' }, false],
    ['aboutYou 4-word run', 'This matters for Alpha Pet Supplies owners.', { aboutYou: 'I run Alpha Pet Supplies and I do not code' }, false],
    ['filePath windows basename', 'Edit payments-settings.ts.', { filePath: 'C:\\Users\\a\\src\\payments-settings.ts' }, false],
    ['filePath no-ext basename', 'Check the payments-settings module.', { filePath: 'src/payments-settings' }, false],
    ['snippet line <16 chars', 'Remove apiKey = k1 now.', { codeSnippet: 'apiKey = k1' }, false],
    // Limit: a 4-word overlap with the scanner message is too common in normal
    // prose to reject on ("found in the config"). Six words or more are rejected.
    ['rawMessage 4-word overlap (limit)', 'The key was found in Alpha config.', { rawMessage: 'AWS key found in alpha config file line 12' }, true],
    ['rawMessage 6-word run', 'The key found in alpha config file is live.', { rawMessage: 'AWS key found in alpha config file line 12' }, false],
  ]
  const wrong = cases.filter(([, t, u, ok]) => checkSharedExplanation({ simply: t, actions: ['x'] }, u).ok !== ok)
  assertEquals(wrong.map(([n]) => n), [])
})

Deno.test('aboutYouEchoed: whole short text, 5-word runs and capitalised names', () => {
  const hay = (s: string) => s.toLowerCase().replace(/\s+/g, ' ')
  assert(aboutYouEchoed('Alpha Pet Supplies', hay('alpha pet supplies is at risk')))
  assert(aboutYouEchoed('I run Northwind Traders and sell tea', hay('northwind traders customers')))
  assert(aboutYouEchoed('I build apps for small vet clinics', hay('apps for small vet clinics are')))
  assertFalse(aboutYouEchoed('I run a bakery', hay('a bakery owner should care')))
  assertFalse(aboutYouEchoed('Founder', hay('every founder should rotate keys')))
  assertFalse(aboutYouEchoed('I do not code', hay('you do not need to code to fix this')))
})

Deno.test('send or visit instructions are rejected, warnings and terminal commands are not', () => {
  const host = `keycheck-${fakeLabel()}.io`
  for (const t of [
    `Paste your key at ${host} to verify it still works.`,
    `Visit ${host} and enter your token.`,
    'Upload your .env file to an online validator to check it.',
    'Paste the token into an online decoder to see what it contains.',
    'Send the secret to our support chat so we can check it.',
    `Go to https://${host}/check and paste the key.`,
    'Submit your credentials on the verification form.',
  ]) {
    assert(hasSendOrVisitInstruction(t), t)
    assert(checkSharedExplanation({ simply: 'x', actions: [t] }).reasons.includes('instruction:send_or_visit'), t)
  }
  for (const t of [
    'Paste this into your terminal: git rm --cached .env',
    'Never paste your key into an online decoder.',
    'Do not send secrets to anyone over chat.',
    "Enter the new key in your hosting provider's environment settings.",
    'Open your Stripe dashboard and roll the key.',
    'Share this with whoever looks after your code.',
    'Ask your developer to rotate the key.',
    'An attacker could go to your login page and try thousands of passwords.',
  ]) {
    assertFalse(hasSendOrVisitInstruction(t), t)
  }
})

Deno.test('normal security prose is not blocked by the tighter checks', () => {
  const prose = [
    'Use parameterized queries (prepared statements) instead of building SQL strings by hand.',
    'Set the HttpOnly, Secure and SameSite flags on session cookies.',
    'Set `HttpOnly`, `Secure` and `SameSite=Lax` on cookies.',
    'Run `npm audit fix` and redeploy.',
    'Run `git rm --cached .env`, then commit.',
    'Use `res.json()` or a template engine that escapes output.',
    'Upgrade lodash to 4.17.21 or later.',
    'CVE-2021-44228 affects Log4j versions 2.0 to 2.14.1.',
    'Hash passwords with bcrypt or argon2; never store them in plain text.',
    'A strong password has at least 12 characters.',
    'Store secrets in environment variables such as STRIPE_SECRET_KEY, not in code.',
    'Restrict database access to your private network, for example 10.0.0.0/8.',
    'Block requests to 127.0.0.1 and 169.254.169.254 from user-supplied URLs.',
    'Attackers often try to read /etc/passwd through path traversal.',
    'Publish a /.well-known/security.txt file so researchers can reach you.',
    'Add the Strict-Transport-Security header with max-age=31536000; includeSubDomains',
    'Send the header X-Content-Type-Options: nosniff on every response.',
    'React escapes text by default; dangerouslySetInnerHTML turns that off.',
    'Install @types/node and @supabase/supabase-js from npm as usual.',
    'Avoid calling eval() on user input.',
    'Enable multi-factor authentication on your GitHub account.',
    'Rotate the key in the provider dashboard, then update it where your app is hosted.',
    'Keep Node.js, Express and Next.js up to date.',
    'Docker containers should not run as root; set a non-root user in the Dockerfile.',
    'Use TLS 1.2 or higher, and turn off SSLv3.',
    'The meeting at 10:30:00 is not an address.',
    'See https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html',
    'Check the CWE-79 entry on cwe.mitre.org for background.',
  ]
  for (const t of prose) {
    assertEquals(checkSharedExplanation({ simply: t, actions: [] }).reasons, [], t)
  }
})
