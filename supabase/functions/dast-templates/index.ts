import { validateToken, corsHeaders } from '../_shared/auth.ts'
import { supabase } from '../_shared/supabase.ts'
import { recordUsage } from '../_shared/usage.ts'
import { getBalance, spendTokens, tokensForAction, InsufficientTokens } from '../_shared/tokens.ts'
import { costMicros, modelInfo, normalizeUsage } from '../_shared/pricing.ts'

interface DastEndpoint {
  url: string
  method: string
  formFields: string[]
  queryParams: string[]
}

interface DastContext {
  targetURL: string
  endpoints: DastEndpoint[]
  techHints: string[]
  maxTemplates: number
}

interface DastTemplateResponse {
  templates: string[]
  rationale: string
}

const DAILY_LIMIT = 100

Deno.serve(async (req) => {
  if (req.method === 'OPTIONS') {
    return json(null, 200, corsHeaders())
  }

  if (req.method !== 'POST') {
    return json({ error: 'Method not allowed' }, 405)
  }

  const token = req.headers.get('authorization')?.replace('Bearer ', '')
  if (!token) return json({ error: 'Unauthorized' }, 401)

  const user = await validateToken(token)
  if (!user) return json({ error: 'Unauthorized' }, 401)

  // Rate limiting — shared with synthesize, capped at 100/day
  const today = new Date().toISOString().slice(0, 10)
  const { data: limitRow } = await supabase
    .from('ai_rate_limit')
    .select('count')
    .eq('user_id', user.id)
    .eq('date', today)
    .single()

  if ((limitRow?.count ?? 0) >= DAILY_LIMIT) {
    return json({
      error: 'rate_limit_exceeded',
      message: 'Daily AI limit reached. Resets at midnight UTC.',
    }, 429)
  }

  const ctx: DastContext = await req.json()

  // Cache check — keyed by crawl content hash
  const crawlHash = computeCrawlHash(ctx)
  console.log(`dast-templates: user=${user.id} crawlHash=${crawlHash} endpoints=${ctx.endpoints?.length ?? 0}`)
  const cached = await getFromCache(crawlHash)
  if (cached) {
    console.log('dast-templates: cache hit')
    // Recorded with cost 0 rather than skipped: cache hit rate moves gross
    // margin directly, so it has to be measurable from the ledger alone.
    await recordUsage({ userId: user.id, feature: 'dast-templates', model: 'claude-haiku-4-5-20251001', cacheHit: true })
    return json(cached)
  }

  // Pre-flight balance gate. Deliberately placed AFTER the cache check: a cache
  // hit costs us nothing, so serving one at zero balance is free money for the
  // customer and zero cost to us. Gating it would deny someone an answer we had
  // already computed and already been paid for.
  //
  // Checked before the paid API call, because the debit below happens once real
  // cost is known -- by which point the spend is already incurred. This cheap
  // read is what stops an empty account spending our money.
  const balance = await getBalance(user.id)
  if (balance <= 0) {
    return json({
      error: 'insufficient_tokens',
      message: 'You are out of Trojan Tokens. Top up to continue.',
      balance,
    }, 402)
  }

  const anthropicKey = Deno.env.get('ANTHROPIC_API_KEY')
  if (!anthropicKey) {
    console.error('dast-templates: ANTHROPIC_API_KEY not set')
    return json({ error: 'Service misconfigured' }, 500)
  }

  const maxTemplates = Math.min(ctx.maxTemplates ?? 10, 10)

  // Build endpoint summary for the prompt (cap to 30 most interesting endpoints)
  const endpointSummary = ctx.endpoints
    .slice(0, 30)
    .map(e => {
      const parts = [`${e.method} ${e.url}`]
      if (e.formFields?.length) parts.push(`  fields: ${e.formFields.join(', ')}`)
      if (e.queryParams?.length) parts.push(`  params: ${e.queryParams.join(', ')}`)
      return parts.join('\n')
    })
    .join('\n\n')

  const techStack = ctx.techHints?.length ? ctx.techHints.join(', ') : 'unknown'

  const prompt = `You are an expert penetration tester writing precise Nuclei v3 YAML templates. Your templates will run against a REAL application — every false positive wastes a developer's time and destroys trust in the tool.

Target: ${ctx.targetURL}
Tech stack: ${techStack}

Discovered endpoints:
${endpointSummary || 'No endpoints discovered — generate generic templates for the target.'}

Generate exactly ${maxTemplates} valid Nuclei v3 YAML templates.

━━━ WHAT TO TEST ━━━
Only generate templates for attack classes that MAKE SENSE for the discovered endpoints:
- SQL/NoSQL injection → only on endpoints with query params or form fields (look for ?id=, ?filter=, ?q=, ?search=, form POST)
- Login form weak auth → if a login/signin endpoint is discovered with form fields (email, password, username):
    * Test SQL injection in the credentials fields (POST with payload like ' OR '1'='1 in the password field)
    * Match on database error strings (SQL syntax error, ORA-, mysql_fetch, pg_query) OR unexpected 200 with auth content
    * DO NOT test brute force or default credentials — Nuclei standard templates already cover that
    * NOTE in the template description: if the app uses a managed auth provider (Supabase, Auth0, Clerk, Cognito), rate limiting and lockout are handled at the platform level and this finding may not apply
- IDOR → only on endpoints with numeric or UUID path segments (e.g. /api/users/123, /docs/abc-def)
- Auth bypass → only on login/auth/admin endpoints (/login, /admin, /api/auth/*)
- XSS → only on endpoints that reflect user input back in HTML (search pages, error messages)
- SSRF → only on endpoints with URL/redirect parameters (?url=, ?redirect=, ?next=)
- Sensitive data exposure → only on API endpoints that return JSON, NOT static HTML pages
- Tech-stack CVEs → only if the tech stack has known exploitable versions

DO NOT generate templates for:
- Static HTML pages (privacy policy, terms of service, marketing pages, docs) — they have no server-side logic
- Endpoints that only return full-page HTML — word matching on HTML is always a false positive
- Numeric IDs on routes that return 404 — the resource doesn't exist, there's nothing to leak
- Brute force or credential stuffing — already covered by Nuclei standard templates, and will lock out dev accounts

━━━ MATCHER RULES (critical — this is where false positives happen) ━━━
Your matchers must verify that the attack WORKED, not just that the page loaded:

For injection (SQL/NoSQL): match on DATABASE ERROR MESSAGES only, not generic words
  Good: ["MongoDB", "MongoError", "CastError", "syntax error", "ORA-", "mysql_fetch", "SQLSTATE"]
  Bad: ["title", "data", "result", "success", "true"]

For IDOR: match on actual SENSITIVE DATA PATTERNS, combined with status:200 AND content-type:json
  Good: status 200 + content-type application/json + words like ["email","password","token","userId"]
  Bad: matching on "title" or any word that appears in HTML pages

For XSS: match on the EXACT PAYLOAD reflected back
  Good: words: ["<script>alert(1)</script>"] with condition: and
  Bad: words: ["script"] or any generic term

For sensitive data exposure: match on machine-readable secrets, not page content
  Good: regex for JWT (eyJ[a-zA-Z0-9_-]+\\.eyJ), API key patterns ([a-z0-9]{32,}), or JSON with {"api_key":, {"secret":
  Bad: words: ["secret", "api_key", "token"] — these appear in docs and marketing copy

For auth bypass: match on response DIFFERENCES (status 200 vs expected 401/403, or presence of authenticated content)
  Good: status: 200 with words specific to logged-in content ["dashboard", "logout", "account"]
  Bad: just status: 200 alone

━━━ TEMPLATE RULES ━━━
- id: trojan-custom-NNN (unique, sequential)
- info: name, author: trojan, severity (critical/high/medium/low), description
- Use "http" key (NOT "requests") — Nuclei v3
- Only ONE matcher block per template (use matcher-condition: and for multi-condition)
- Stop-at-first-match where possible to avoid noise
- Syntactically valid YAML — strings with special characters must be quoted

━━━ EXAMPLE of a GOOD template (NoSQL injection with real error matching) ━━━
id: trojan-custom-001
info:
  name: NoSQL Injection via filter param
  author: trojan
  severity: high
  description: Sends MongoDB operator to filter param and checks for database error response
http:
  - method: GET
    path:
      - '{{BaseURL}}/api/users?filter[$where]=1==1'
    matchers-condition: and
    matchers:
      - type: word
        words:
          - 'MongoError'
          - 'CastError'
          - 'RangeError'
        condition: or
      - type: status
        status:
          - 500

━━━ EXAMPLE of a BAD template (DO NOT do this) ━━━
# This will fire on every page — useless
matchers:
  - type: word
    words:
      - 'title'   # appears in every HTML page
      - 'secret'  # appears in privacy/security marketing pages

Respond with valid JSON only (no markdown, no code fences):

{
  "templates": [
    "id: trojan-custom-001\ninfo:\n  name: ...\n  author: trojan\n  severity: high\n  description: ...\nhttp:\n  - method: GET\n    path:\n      - '{{BaseURL}}/api/endpoint?param=value'\n    matchers-condition: and\n    matchers:\n      - type: word\n        words:\n          - 'SpecificErrorOrDataPattern'\n      - type: status\n        status:\n          - 200\n"
  ],
  "rationale": "Which attack classes you chose, which you skipped and why"
}`

  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), 45_000)

  let resp: Response
  try {
    resp = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'x-api-key': anthropicKey,
        'anthropic-version': '2023-06-01',
        'content-type': 'application/json',
      },
      signal: controller.signal,
      body: JSON.stringify({
        model: 'claude-haiku-4-5-20251001',
        max_tokens: 6000,
        system: 'You are a security expert generating Nuclei YAML templates. Always respond with raw JSON only — no markdown, no code fences, no explanation outside the JSON object.',
        messages: [{ role: 'user', content: prompt }],
      }),
    })
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err)
    console.error('dast-templates: Anthropic fetch failed:', msg)
    return json({ error: `AI service error: ${msg}` }, 500)
  } finally {
    clearTimeout(timer)
  }

  if (!resp.ok) {
    const body = await resp.text().catch(() => '')
    console.error(`dast-templates: Anthropic API error ${resp.status}:`, body)
    return json({ error: `AI service error (${resp.status})` }, 500)
  }

  const completion = await resp.json()
  const raw: string = completion.content?.[0]?.text ?? ''
  const text = raw.replace(/^```(?:json)?\s*/i, '').replace(/\s*```\s*$/, '').trim()

  let result: DastTemplateResponse
  try {
    const parsed = JSON.parse(text) as DastTemplateResponse
    if (!Array.isArray(parsed.templates) || parsed.templates.length === 0) {
      throw new Error('unexpected shape')
    }
    // Validate each template has minimum required keys
    const valid = parsed.templates.filter(t =>
      typeof t === 'string' &&
      t.includes('id:') &&
      (t.includes('http:') || t.includes('requests:'))
    )
    if (valid.length === 0) throw new Error('no valid templates after filtering')
    result = { templates: valid, rationale: parsed.rationale ?? '' }
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err)
    console.error('Template parse/validation failed:', msg, '\nRaw response:', raw.slice(0, 500))
    return json({ error: `Failed to generate valid templates: ${msg}` }, 500)
  }

  await saveToCache(crawlHash, result)

  // Increment rate limit — count as 1 call regardless of template count
  await supabase.from('ai_rate_limit').upsert({
    user_id: user.id,
    date: today,
    count: (limitRow?.count ?? 0) + 1,
  }, { onConflict: 'user_id,date' })

  await recordUsage({
    userId:  user.id,
    feature: 'dast-templates',
    model:   'claude-haiku-4-5-20251001',
    usage:   completion.usage,
  })

  // Debit the real cost of this call.
  try {
    const info = modelInfo('claude-haiku-4-5-20251001')
    const norm = normalizeUsage(info?.provider ?? 'anthropic', completion.usage)
    const cost = costMicros('claude-haiku-4-5-20251001', norm)
    await spendTokens({
      userId:     user.id,
      tokens:     tokensForAction('dast-templates', cost),
      feature:    'dast-templates',
      model:      'claude-haiku-4-5-20251001',
      costMicros: cost,
      idempotencyKey: `dast-templates:${user.id}:${crawlHash}`,
    })
  } catch (e) {
    // The work is already done and already cost us money, so the result is
    // returned regardless. A zero balance simply stops the NEXT call at the
    // pre-flight gate above.
    if (e instanceof InsufficientTokens) {
      console.warn('dast-templates: balance exhausted after work was performed', { userId: user.id })
    } else {
      throw e
    }
  }

  return json(result)
})

async function getFromCache(crawlHash: string): Promise<DastTemplateResponse | null> {
  const { data, error } = await supabase
    .from('dast_template_cache')
    .select('templates, rationale, created_at')
    .eq('crawl_hash', crawlHash)
    .single()

  if (error && error.code !== 'PGRST116') {
    // PGRST116 = no rows found (expected); anything else is a real DB error
    console.error('dast-templates: cache read error:', error.message, error.code)
  }
  if (!data) return null

  // TTL: 24 hours
  const age = Date.now() - new Date(data.created_at as string).getTime()
  if (age > 24 * 60 * 60 * 1000) return null

  return {
    templates: data.templates as string[],
    rationale: data.rationale as string ?? '',
  }
}

async function saveToCache(crawlHash: string, result: DastTemplateResponse): Promise<void> {
  const { error } = await supabase.from('dast_template_cache').upsert({
    crawl_hash: crawlHash,
    templates: result.templates,
    rationale: result.rationale,
  }, { onConflict: 'crawl_hash' })
  if (error) console.error('dast-templates: cache write error:', error.message, error.code)
}

function computeCrawlHash(ctx: DastContext): string {
  const urls = ctx.endpoints.map(e => `${e.method}:${e.url}`).sort()
  const hints = [...(ctx.techHints ?? [])].sort()
  const raw = `${ctx.targetURL}|${urls.join(',')}|${hints.join(',')}`
  // Simple hash — sufficient for cache keying
  let h = 0
  for (let i = 0; i < raw.length; i++) {
    h = (Math.imul(31, h) + raw.charCodeAt(i)) | 0
  }
  return (h >>> 0).toString(16).padStart(8, '0')
}

function json(data: unknown, status = 200, extraHeaders: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...corsHeaders(), 'Content-Type': 'application/json', ...extraHeaders },
  })
}
