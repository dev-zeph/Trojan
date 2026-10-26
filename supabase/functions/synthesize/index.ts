import { validateToken, corsHeaders } from '../_shared/auth.ts'
import { supabase } from '../_shared/supabase.ts'
import { recordUsage } from '../_shared/usage.ts'
import { getBalance, spendTokens, tokensForAction, InsufficientTokens } from '../_shared/tokens.ts'
import { costMicros, modelInfo, normalizeUsage } from '../_shared/pricing.ts'

interface FindingMeta {
  ruleId: string
  scanner: string
  category: string
  severity: string
  title: string
  rawMessage: string
  language?: string
  filePath?: string
  codeSnippet?: string
  surroundingCode?: string
  projectType?: string
  framework?: string
  familiarity?: number  // 0 = non-technical, 1 = junior dev, 2 = experienced
  aboutYou?: string     // free-form user context
}

interface Synthesis {
  simply: string
  actions: string[]
}

const TONE_INSTRUCTIONS: Record<number, string> = {
  0: `You are this person's trusted security consultant. They are a NON-TECHNICAL founder — they do NOT know what libraries, parsers, headers, protocols, dependencies, or servers are. Do NOT use ANY of these words.

RULES FOR "simply":
- Start by telling them how dangerous this is in plain terms: "This is a serious/moderate/minor security problem."
- Explain the BUSINESS IMPACT: could someone steal customer data? Could the app crash? Could someone break in?
- Use analogies a business person would understand (locks, doors, security guards — not code concepts).
- NEVER mention library names, function names, file formats, or programming concepts.
- Maximum 2-3 short sentences. A 10-year-old should be able to understand it.

RULES FOR "actions":
- Tell them exactly what to DO, step by step, as if writing instructions for someone who has never opened a terminal.
- If they need to run a command, write the exact command and say "paste this into your terminal."
- If they need a developer's help, say so: "Ask your developer to..."`,

  1: `The user is a junior developer with limited security experience. Explain security concepts as you introduce them — don't assume they know what XSS, injection, or CVE means. Use simple, clear language. Give practical step-by-step instructions. Avoid dense jargon but it's okay to reference file names and commands.`,

  2: `The user is an experienced developer comfortable with security concepts. Be concise and technical — use standard security terminology, reference CWEs/CVEs where relevant, and assume they understand code patterns and frameworks.`,
}

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

  const finding: FindingMeta = await req.json()

  const anthropicKey = Deno.env.get('ANTHROPIC_API_KEY')
  if (!anthropicKey) {
    console.error('synthesize: ANTHROPIC_API_KEY not set')
    return json({ error: 'Service misconfigured' }, 500)
  }

  const famLevel = finding.familiarity ?? 1
  console.log(`synthesize: user=${user.id} rule=${finding.ruleId} scanner=${finding.scanner} familiarity=${famLevel}`)

  // Check cache — keyed by rule + scanner + familiarity
  const cached = await getFromCache(finding.ruleId, finding.scanner, famLevel)
  if (cached) {
    console.log('synthesize: cache hit')
    // Recorded with cost 0 rather than skipped: cache hit rate moves gross
    // margin directly, so it has to be measurable from the ledger alone.
    await recordUsage({ userId: user.id, feature: 'synthesize', model: 'claude-haiku-4-5-20251001', cacheHit: true })
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

  const toneInstruction = TONE_INSTRUCTIONS[famLevel] ?? TONE_INSTRUCTIONS[1]
  const userContext = finding.aboutYou
    ? `\n\nAdditional context about the user:\n${finding.aboutYou}`
    : ''

  const codeContext = [
    finding.language ? `Language: ${finding.language}` : null,
    finding.framework ? `Framework: ${finding.framework}` : null,
    finding.projectType ? `Project type: ${finding.projectType}` : null,
    finding.filePath ? `File: ${finding.filePath}` : null,
  ].filter(Boolean).join('\n')

  const prompt = `${toneInstruction}
${userContext ? `\nThe user told you about themselves:\n"${finding.aboutYou}"\n\nRespect this completely. If they say they are non-technical, do NOT use technical language.\n` : ''}
Here is a security issue found in their project. Explain it to them according to the rules above.

Title: ${finding.title}
Severity: ${finding.severity}
Scanner description: ${finding.rawMessage}
${codeContext ? `\n${codeContext}` : ''}

Respond with ONLY a JSON object, no markdown, no code fences:
{
  "simply": "2-3 sentence explanation following the tone rules above",
  "actions": ["step 1", "step 2", "step 3"]
}`

  // Call Anthropic API using raw fetch (same pattern as threat-lab)
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), 30_000)

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
        max_tokens: 1024,
        messages: [{ role: 'user', content: prompt }],
      }),
    })
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err)
    console.error('synthesize: Anthropic fetch failed:', msg)
    return json({ error: `AI service error: ${msg}` }, 500)
  } finally {
    clearTimeout(timer)
  }

  if (!resp.ok) {
    const body = await resp.text().catch(() => '')
    console.error(`synthesize: Anthropic API error ${resp.status}:`, body)
    return json({ error: `AI service error (${resp.status})` }, 500)
  }

  const completion = await resp.json()
  const raw: string = completion.content?.[0]?.text ?? ''

  if (!raw) {
    console.error('synthesize: empty response from Anthropic')
    return json({ error: 'AI returned empty response' }, 500)
  }

  // Strip markdown fences if Claude wraps the JSON
  const text = raw.replace(/^```(?:json)?\s*/i, '').replace(/\s*```\s*$/, '').trim()

  let synthesis: Synthesis
  try {
    synthesis = JSON.parse(text) as Synthesis
    if (!synthesis.simply || !Array.isArray(synthesis.actions)) {
      throw new Error('unexpected shape')
    }
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err)
    console.error('synthesize: JSON parse failed:', msg, '\nRaw:', text.slice(0, 300))
    return json({ error: `Failed to parse AI response: ${msg}` }, 500)
  }

  // Cache by rule + scanner + familiarity so tone changes regenerate
  await saveToCache(finding.ruleId, finding.scanner, famLevel, synthesis)

  console.log(`synthesize: success rule=${finding.ruleId}`)
  await recordUsage({
    userId:  user.id,
    feature: 'synthesize',
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
      tokens:     tokensForAction('synthesize', cost),
      feature:    'synthesize',
      model:      'claude-haiku-4-5-20251001',
      costMicros: cost,
      // No natural idempotency key: this call has no stable content hash.
      // A retried request can therefore double-charge, which is acceptable
      // here because the amount is a few tokens on a Haiku call.
    })
  } catch (e) {
    // The work is already done and already cost us money, so the result is
    // returned regardless. A zero balance simply stops the NEXT call at the
    // pre-flight gate above.
    if (e instanceof InsufficientTokens) {
      console.warn('synthesize: balance exhausted after work was performed', { userId: user.id })
    } else {
      throw e
    }
  }

  return json(synthesis)
})

async function getFromCache(ruleId: string, scanner: string, familiarity: number): Promise<Synthesis | null> {
  // maybeSingle(), not single(): single() raises both on zero rows and on
  // duplicates, and the error was previously swallowed by destructuring only
  // { data } -- which made a broken cache indistinguishable from a cold one.
  const { data, error } = await supabase
    .from('ai_cache')
    .select('simply, actions')
    .eq('rule_id', ruleId)
    .eq('scanner', scanner)
    .eq('familiarity', familiarity)
    .maybeSingle()

  if (error) {
    console.error('synthesize: cache READ failed', {
      ruleId, scanner, familiarity, error: error.message,
    })
    return null
  }
  if (!data) return null
  return { simply: data.simply as string, actions: data.actions as string[] }
}

async function saveToCache(ruleId: string, scanner: string, familiarity: number, synthesis: Synthesis): Promise<void> {
  // onConflict names the unique index added in migration 011. Without a conflict
  // target PostgREST falls back to the primary key -- a generated uuid -- so
  // every write INSERTed a fresh duplicate instead of updating, which then broke
  // the read path above. Errors are surfaced rather than silently dropped.
  const { error } = await supabase.from('ai_cache').upsert({
    rule_id: ruleId,
    scanner,
    familiarity,
    simply: synthesis.simply,
    actions: synthesis.actions,
  }, { onConflict: 'rule_id,scanner,familiarity' })

  if (error) {
    console.error('synthesize: cache WRITE failed', {
      ruleId, scanner, familiarity, error: error.message,
    })
  }
}

function json(data: unknown, status = 200, extraHeaders: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...corsHeaders(), 'Content-Type': 'application/json', ...extraHeaders },
  })
}
