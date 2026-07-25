import { validateToken, isPro, corsHeaders } from '../_shared/auth.ts'
import { supabase } from '../_shared/supabase.ts'

// ── Input types ──────────────────────────────────────────────────────────

interface LicenseSummary {
  total_packages: number
  copyleft: { name: string; version: string; license: string }[]
  weak_copyleft: { name: string; license: string }[]
  unknown_count: number
  permissive_count: number
}

interface PrivacySummary {
  data_types: { name: string; category: string; detection_count: number }[]
  third_party: { name: string; data_types: string[] }[]
}

interface ComplianceLabRequest {
  project_path: string
  licenses: LicenseSummary
  privacy: PrivacySummary
  // Report audience: 0 = executive, 1 = tech lead, 2 = auditor
  user_familiarity?: number
}

// ── Output types ─────────────────────────────────────────────────────────

interface ComplianceLabResult {
  grade: 'A' | 'B' | 'C' | 'D' | 'F'
  score: number                    // 0–100 (higher = more compliant)
  executive_summary: string        // 2–3 sentence overview
  license_verdict: string          // paragraph on license posture
  privacy_verdict: string          // paragraph on privacy/data handling posture
  recommendations: string[]        // 3–5 actionable next steps
}

// ── Constants ────────────────────────────────────────────────────────────

const DAILY_LIMIT = 20
const CACHE_TTL_MS = 6 * 60 * 60 * 1000

// ── Main handler ─────────────────────────────────────────────────────────

Deno.serve(async (req) => {
  if (req.method === 'OPTIONS') return json(null, 200, corsHeaders())

  try {
    return await handleRequest(req)
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err)
    console.error('compliance-lab: unhandled exception:', msg)
    return json({ error: 'Internal server error' }, 500)
  }
})

async function handleRequest(req: Request): Promise<Response> {
  if (req.method !== 'POST') return json({ error: 'Method not allowed' }, 405)

  const token = req.headers.get('authorization')?.replace('Bearer ', '')
  if (!token) return json({ error: 'Unauthorized' }, 401)

  const user = await validateToken(token)
  if (!user) return json({ error: 'Unauthorized' }, 401)
  if (!isPro(user)) return json({ error: 'Pro subscription required' }, 403)

  // Rate limiting
  const today = new Date().toISOString().slice(0, 10)
  const { data: limitRow } = await supabase
    .from('ai_rate_limit')
    .select('count')
    .eq('user_id', user.id)
    .eq('date', today)
    .single()

  if ((limitRow?.count ?? 0) >= DAILY_LIMIT) {
    return json({ error: 'rate_limit_exceeded', message: 'Daily limit reached. Resets at midnight UTC.' }, 429)
  }

  let body: ComplianceLabRequest
  try {
    body = await req.json()
  } catch {
    return json({ error: 'Invalid JSON body' }, 400)
  }

  const { project_path = '', licenses, privacy, user_familiarity = 1 } = body
  const familiarity = Math.max(0, Math.min(2, Math.round(user_familiarity)))

  const inputHash = computeHash({ licenses, privacy, familiarity })
  console.log(`compliance-lab: user=${user.id} hash=${inputHash} familiarity=${familiarity}`)

  const cached = await getFromCache(user.id, inputHash)
  if (cached) {
    console.log('compliance-lab: cache hit')
    return json(cached)
  }

  const anthropicKey = Deno.env.get('ANTHROPIC_API_KEY')
  if (!anthropicKey) {
    console.error('compliance-lab: ANTHROPIC_API_KEY not set')
    return json({ error: 'Service misconfigured' }, 500)
  }

  const prompt = buildPrompt(project_path, licenses, privacy)

  const familiarityInstruction = familiarity === 0
    ? `The report audience is EXECUTIVE / NON-TECHNICAL STAKEHOLDERS.
- Use plain English. No jargon. Focus on business risk: legal exposure, fines, customer trust.
- Explain what "copyleft" means in simple terms. Explain what PII means.
- Recommendations should be one sentence each, action-oriented.
- This report will be shared with investors or board members.`
    : familiarity === 2
    ? `The report audience is LEGAL/COMPLIANCE or SECURITY AUDITORS.
- Use precise regulatory language: cite specific regulations (GDPR Art. 6, PIPEDA Principle 4.3, etc.).
- Name specific licenses and their obligations.
- Recommendations should reference specific compliance frameworks.`
    : `The report audience is TECHNICAL LEADS or PRODUCT MANAGERS.
- Balance plain language with technical accuracy.
- Name the specific packages and data types.
- Recommendations should be actionable by a development team.`

  const systemPrompt = `You are a compliance analyst assessing a software project's regulatory and licensing posture.
You will receive license data and privacy data flow information.
Your job is to assess whether the project is compliant-safe from a licensing and data-handling perspective.

${familiarityInstruction}

Respond with a single JSON object matching the ComplianceLabResult schema — no markdown, no code fences, no text outside the JSON.`

  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), 60_000)

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
        model: 'claude-sonnet-4-6',
        max_tokens: 2048,
        system: systemPrompt,
        messages: [{ role: 'user', content: prompt }],
      }),
    })
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err)
    console.error('Anthropic fetch failed:', msg)
    return json({ error: `AI request failed: ${msg}` }, 500)
  } finally {
    clearTimeout(timer)
  }

  if (!resp.ok) {
    const body = await resp.text().catch(() => '')
    console.error(`Anthropic API error ${resp.status}:`, body)
    return json({ error: `AI service error (${resp.status})` }, 500)
  }

  let completion: { content?: { text?: string }[] }
  try {
    completion = await resp.json()
  } catch {
    return json({ error: 'AI service returned an unexpected response' }, 500)
  }
  const raw: string = completion.content?.[0]?.text ?? ''
  const text = raw.replace(/^```(?:json)?\s*/i, '').replace(/\s*```\s*$/, '').trim()

  let result: ComplianceLabResult
  try {
    result = JSON.parse(text) as ComplianceLabResult
    // Coerce score to number — AI sometimes returns it as a string
    result.score = Number(result.score)
    if (!result.grade || isNaN(result.score) || !result.executive_summary) {
      throw new Error('Missing required fields')
    }
    result.score = Math.max(0, Math.min(100, result.score))
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err)
    console.error('compliance-lab: parse failed:', msg, '\nRaw:', raw.slice(0, 500))
    return json({ error: `Failed to parse AI response: ${msg}` }, 500)
  }

  await saveToCache(user.id, inputHash, result)

  await supabase.from('ai_rate_limit').upsert({
    user_id: user.id,
    date: today,
    count: (limitRow?.count ?? 0) + 1,
  }, { onConflict: 'user_id,date' })

  console.log(`compliance-lab: done grade=${result.grade} score=${result.score}`)
  return json(result)
}

// ── Prompt builder ───────────────────────────────────────────────────────

function buildPrompt(projectPath: string, lic: LicenseSummary, priv: PrivacySummary): string {
  const projectName = projectPath.split('/').pop() || 'unknown'

  const copyleftLines = lic.copyleft.length > 0
    ? lic.copyleft.map(p => `  - ${p.name}@${p.version} (${p.license})`).join('\n')
    : '  None'

  const weakLines = lic.weak_copyleft.length > 0
    ? lic.weak_copyleft.slice(0, 10).map(p => `  - ${p.name} (${p.license})`).join('\n')
    : '  None'

  const privDataLines = priv.data_types.length > 0
    ? priv.data_types.map(d => `  - ${d.name} (${d.category}) — ${d.detection_count} detections`).join('\n')
    : '  No personal data detected'

  const thirdPartyLines = priv.third_party.length > 0
    ? priv.third_party.map(t => `  - ${t.name}: shares ${(t.data_types ?? []).filter(d => d !== 'Unknown').join(', ') || 'unidentified data'}`).join('\n')
    : '  No third-party integrations detected'

  return `Project: ${projectName}

## License Summary
- Total packages: ${lic.total_packages}
- Permissive (MIT, BSD, Apache, etc.): ${lic.permissive_count}
- Unknown / no license declared: ${lic.unknown_count}
- Weak copyleft (LGPL, MPL): ${lic.weak_copyleft.length}
- Copyleft (GPL, AGPL — may require open-sourcing):
${copyleftLines}

Weak copyleft packages:
${weakLines}

## Privacy Data Flows
Personal data types detected:
${privDataLines}

Third-party data recipients:
${thirdPartyLines}

Respond with ONLY a JSON object matching this schema:
{
  "grade": "<A|B|C|D|F>",
  "score": <0-100, where 100 = fully compliant>,
  "executive_summary": "<2-3 sentence overview of the project's compliance posture>",
  "license_verdict": "<paragraph explaining the license situation — risks, obligations, and whether the dependency tree is safe for commercial use>",
  "privacy_verdict": "<paragraph explaining the privacy/data handling situation — what PII is processed, who receives it, and what regulations may apply>",
  "recommendations": ["<action 1>", "<action 2>", "..."]
}

Grading guide:
- A (90-100): No copyleft, no unknown licenses, minimal PII, all data flows accounted for
- B (75-89): Minor issues — a few unknown licenses or PII types, but manageable
- C (60-74): Needs attention — copyleft risk or significant PII handling without clear policies
- D (40-59): Serious gaps — copyleft contamination or uncontrolled PII flows to third parties
- F (0-39): Critical — legal exposure from licensing or privacy violations

Rules:
- Be specific: name the packages and data types that matter
- recommendations: exactly 3-5 actionable items
- No markdown, no code fences, raw JSON only`
}

// ── Cache helpers ────────────────────────────────────────────────────────

async function getFromCache(userId: string, inputHash: string): Promise<ComplianceLabResult | null> {
  const { data, error } = await supabase
    .from('compliance_lab_cache')
    .select('result, created_at')
    .eq('user_id', userId)
    .eq('input_hash', inputHash)
    .single()

  if (error && error.code !== 'PGRST116') {
    console.error('compliance-lab: cache read error:', error.message)
  }
  if (!data) return null

  const age = Date.now() - new Date(data.created_at as string).getTime()
  if (age > CACHE_TTL_MS) return null

  return data.result as ComplianceLabResult
}

async function saveToCache(userId: string, inputHash: string, result: ComplianceLabResult): Promise<void> {
  const { error } = await supabase.from('compliance_lab_cache').upsert({
    user_id: userId,
    input_hash: inputHash,
    result,
  }, { onConflict: 'user_id,input_hash' })
  if (error) console.error('compliance-lab: cache write error:', error.message)
}

// ── Utilities ────────────────────────────────────────────────────────────

function computeHash(data: object): string {
  const raw = JSON.stringify(data)
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
