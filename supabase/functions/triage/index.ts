import { validateToken, corsHeaders } from '../_shared/auth.ts'
import { supabase } from '../_shared/supabase.ts'
import { parseBody } from '../_shared/body.ts'
import { recordUsage } from '../_shared/usage.ts'
import { getBalance, spendTokens, tokensForAction, InsufficientTokens } from '../_shared/tokens.ts'
import { costMicros, modelInfo, normalizeUsage } from '../_shared/pricing.ts'

// Phase 1 of agentic DAST (docs/agentic-dast.md §7): adversarial false-positive
// triage. Takes a batch of raw scanner findings (Nuclei/DAST or SAST) plus their
// evidence and asks Claude to REFUTE each one — anchoring on the actual HTTP
// response / matched evidence, not the scanner's say-so. Returns a verdict per
// finding so the UI can separate confirmed issues from noise. No new attack
// traffic — pure reasoning over evidence already collected.
//
// Bodies are base64-wrapped by the client ({ encoded }) so Cloudflare's WAF
// doesn't 403 on the attack signatures inside findings — see _shared/body.ts.

interface FindingIn {
  id: string
  title: string
  severity: string
  category?: string        // e.g. "dast", "sast", "secrets"
  ruleId?: string          // template-id / rule that fired
  matchedAt?: string       // URL or file:line the match anchored to
  evidence?: string        // the request snippet / matched string
  responseSnippet?: string // the actual HTTP response (or code context)
  agreedScanners?: string[] // every engine that independently reported this (corroboration)
}

interface Verdict {
  id: string
  verdict: 'confirmed' | 'likely_fp' | 'needs_manual'
  confidence: number       // 0..1
  rationale: string
}

const DAILY_LIMIT = 100
const MAX_FINDINGS = 40    // one call handles a batch; cap to keep tokens bounded

Deno.serve(async (req) => {
  if (req.method === 'OPTIONS') return json(null, 200, corsHeaders())
  if (req.method !== 'POST') return json({ error: 'Method not allowed' }, 405)

  const token = req.headers.get('authorization')?.replace('Bearer ', '')
  if (!token) return json({ error: 'Unauthorized' }, 401)

  const user = await validateToken(token)
  if (!user) return json({ error: 'Unauthorized' }, 401)
  // Pre-flight balance gate, before the paid API call -- the debit happens
  // afterwards when real cost is known, by which point the spend is already
  // incurred. This cheap read is what stops an empty account spending our money.
  // A cache hit below is free and never reaches this, so repeat requests for the
  // same input keep working at zero balance.
  const balance = await getBalance(user.id)
  if (balance <= 0) {
    return json({
      error: 'insufficient_tokens',
      message: 'You are out of Trojan Tokens. Top up to continue.',
      balance,
    }, 402)
  }

  // Rate limiting — shared bucket with synthesize / dast-templates, 100/day.
  const today = new Date().toISOString().slice(0, 10)
  const { data: limitRow } = await supabase
    .from('ai_rate_limit')
    .select('count')
    .eq('user_id', user.id)
    .eq('date', today)
    .single()

  if ((limitRow?.count ?? 0) >= DAILY_LIMIT) {
    return json({ error: 'rate_limit_exceeded', message: 'Daily AI limit reached. Resets at midnight UTC.' }, 429)
  }

  let body: { findings?: FindingIn[] }
  try {
    body = await parseBody<{ findings?: FindingIn[] }>(req)
  } catch {
    return json({ error: 'Invalid JSON body' }, 400)
  }

  const findings = (body.findings ?? []).slice(0, MAX_FINDINGS)
  if (findings.length === 0) return json({ verdicts: [] })

  const anthropicKey = Deno.env.get('ANTHROPIC_API_KEY')
  if (!anthropicKey) {
    console.error('triage: ANTHROPIC_API_KEY not set')
    return json({ error: 'Service misconfigured' }, 500)
  }

  const findingsBlock = findings.map((f, i) => {
    const parts = [
      `#${i} id=${f.id}`,
      `  title: ${f.title}`,
      `  severity: ${f.severity}`,
      f.category ? `  category: ${f.category}` : '',
      f.ruleId ? `  rule: ${f.ruleId}` : '',
      f.matchedAt ? `  matched_at: ${f.matchedAt}` : '',
      f.evidence ? `  evidence: ${truncate(f.evidence, 800)}` : '',
      f.responseSnippet ? `  response/context:\n${indent(truncate(f.responseSnippet, 1500))}` : '',
      f.agreedScanners && f.agreedScanners.length > 1
        ? `  corroboration: independently reported by ${f.agreedScanners.length} scanners (${f.agreedScanners.join(', ')})`
        : '',
    ].filter(Boolean)
    return parts.join('\n')
  }).join('\n\n')

  const prompt = `You are a senior security reviewer performing FALSE-POSITIVE TRIAGE on automated scanner findings. Automated scanners (Nuclei, SAST engines) are noisy: they flag "exposed .env" on a 200-returning SPA fallback, "XSS" on an escaped reflection, CVEs for versions not actually running. Your job is to REFUTE each finding using the evidence provided — decide whether the scanner actually proved the issue.

For each finding, reason adversarially: what would make this a FALSE POSITIVE? Only mark it "confirmed" if the evidence itself demonstrates the vulnerability (e.g. the response body actually contains the sensitive data, the payload is actually reflected unescaped, the error string actually indicates injection). If the evidence is ambiguous, or confirming would require information you don't have, default to "needs_manual" — never "confirmed" on a hunch. Use "likely_fp" when the evidence points to a benign explanation.

When a finding shows "corroboration" (multiple independent scanners flagged the same issue at the same location), treat that as a modest confidence boost toward the issue being real — independent engines rarely produce the same false positive. It is a supporting signal, not proof: it can raise confidence and tip a borderline finding away from "likely_fp", but it must NOT by itself turn evidence-free or contradicted findings into "confirmed" — the evidence still governs the verdict.

Findings:

${findingsBlock}

Respond with raw JSON only (no markdown, no code fences):
{
  "verdicts": [
    { "id": "<finding id>", "verdict": "confirmed" | "likely_fp" | "needs_manual", "confidence": 0.0-1.0, "rationale": "one or two sentences grounded in the evidence" }
  ]
}
Return exactly one verdict per finding, keyed by its id.`

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
        max_tokens: 4000,
        system: 'You are a security expert triaging scanner findings for false positives. Always respond with raw JSON only — no markdown, no code fences, no prose outside the JSON object. Be skeptical: default to needs_manual when the evidence does not clearly prove the issue.',
        messages: [{ role: 'user', content: prompt }],
      }),
    })
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err)
    console.error('triage: Anthropic fetch failed:', msg)
    return json({ error: `AI service error: ${msg}` }, 500)
  } finally {
    clearTimeout(timer)
  }

  if (!resp.ok) {
    const errBody = await resp.text().catch(() => '')
    console.error(`triage: Anthropic API error ${resp.status}:`, errBody)
    return json({ error: `AI service error (${resp.status})` }, 500)
  }

  const completion = await resp.json()
  const raw: string = completion.content?.[0]?.text ?? ''
  const text = raw.replace(/^```(?:json)?\s*/i, '').replace(/\s*```\s*$/, '').trim()

  let verdicts: Verdict[]
  try {
    const parsed = JSON.parse(text) as { verdicts?: Verdict[] }
    if (!Array.isArray(parsed.verdicts)) throw new Error('unexpected shape')
    const byId = new Map(parsed.verdicts.map(v => [v.id, v]))
    // Guarantee one verdict per input finding; anything the model dropped
    // becomes needs_manual so nothing is silently lost.
    verdicts = findings.map(f => {
      const v = byId.get(f.id)
      if (v && (v.verdict === 'confirmed' || v.verdict === 'likely_fp' || v.verdict === 'needs_manual')) {
        return { id: f.id, verdict: v.verdict, confidence: clamp01(v.confidence), rationale: v.rationale ?? '' }
      }
      return { id: f.id, verdict: 'needs_manual', confidence: 0, rationale: 'No verdict returned; flagged for manual review.' }
    })
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err)
    console.error('triage: parse failed:', msg, '\nRaw:', raw.slice(0, 500))
    return json({ error: `Failed to triage findings: ${msg}` }, 500)
  }

  await supabase.from('ai_rate_limit').upsert({
    user_id: user.id,
    date: today,
    count: (limitRow?.count ?? 0) + 1,
  }, { onConflict: 'user_id,date' })

  await recordUsage({
    userId:  user.id,
    feature: 'triage',
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
      tokens:     tokensForAction('triage', cost),
      feature:    'triage',
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
      console.warn('triage: balance exhausted after work was performed', { userId: user.id })
    } else {
      throw e
    }
  }

  return json({ verdicts })
})

function truncate(s: string, n: number): string {
  return s.length <= n ? s : s.slice(0, n) + '…[truncated]'
}

function indent(s: string): string {
  return s.split('\n').map(l => '    ' + l).join('\n')
}

function clamp01(n: unknown): number {
  const x = typeof n === 'number' ? n : 0
  return x < 0 ? 0 : x > 1 ? 1 : x
}

function json(data: unknown, status = 200, extraHeaders: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...corsHeaders(), 'Content-Type': 'application/json', ...extraHeaders },
  })
}
