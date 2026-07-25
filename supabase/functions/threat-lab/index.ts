import { validateToken, isPro, corsHeaders } from '../_shared/auth.ts'
import { supabase } from '../_shared/supabase.ts'

// ── Input types (matching Go normalizer types) ─────────────────────────────

// Field names match Go's encoding/json defaults (no json tags on Finding struct)
interface Finding {
  ID: string
  Title: string
  Severity: string
  Scanner: string
  FilePath?: string
  LineNumber?: number
}

interface PackageAdvisory {
  id: string
  severity: 'critical' | 'high' | 'medium' | 'low'
  summary: string
  fix_version?: string
}

interface Package {
  name: string
  version: string
  ecosystem: string
  direct: boolean
  cve_count: number
  highest_severity?: string
  fix_version?: string
  advisories?: PackageAdvisory[]
}

interface ThreatLabRequest {
  project_path: string
  findings: Finding[]
  packages: Package[]
  // Optional DAST data
  dast_findings?: Finding[]
  // Report audience: 0 = executive/non-technical, 1 = tech lead, 2 = security engineer/auditor
  user_familiarity?: number
}

// ── Output types ───────────────────────────────────────────────────────────

interface AttackVector {
  title: string
  severity: 'critical' | 'high' | 'medium' | 'low'
  description: string
  findings_involved: string[]  // finding IDs or package names
  exploitability: 'easy' | 'moderate' | 'hard'
}

interface PriorityFix {
  rank: number
  type: 'code' | 'package' | 'config'
  title: string
  description: string
  // For package fixes — the install command
  command?: string
  // For code fixes — file and line hint
  file?: string
  line?: number
  finding_id?: string
}

interface ThreatLabResult {
  threat_index: number        // 0–100
  grade: 'A' | 'B' | 'C' | 'D' | 'F'
  verdict: string             // 1–2 sentence executive summary
  attack_vectors: AttackVector[]
  priority_fixes: PriorityFix[]
  compliance_summary: string  // OWASP / CWE coverage notes
  key_risks: string[]         // 3–5 bullet-point risks
}

// ── Constants ──────────────────────────────────────────────────────────────

const DAILY_LIMIT = 20   // Threat Lab calls are expensive — lower cap than dast-templates
const CACHE_TTL_MS = 6 * 60 * 60 * 1000  // 6 hours

// ── Main handler ───────────────────────────────────────────────────────────

Deno.serve(async (req) => {
  // OPTIONS must be handled before the try-catch so preflight always succeeds.
  if (req.method === 'OPTIONS') {
    return json(null, 200, corsHeaders())
  }

  // Top-level guard: any uncaught exception still returns CORS headers so the
  // browser can read the error body instead of seeing a opaque network failure.
  try {
    return await handleRequest(req)
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err)
    console.error('threat-lab: unhandled exception:', msg)
    return json({ error: 'Internal server error' }, 500)
  }
})

async function handleRequest(req: Request): Promise<Response> {
  if (req.method !== 'POST') {
    return json({ error: 'Method not allowed' }, 405)
  }

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
    return json({
      error: 'rate_limit_exceeded',
      message: 'Daily Threat Lab limit reached. Resets at midnight UTC.',
    }, 429)
  }

  let body: ThreatLabRequest
  try {
    body = await req.json()
  } catch {
    return json({ error: 'Invalid JSON body' }, 400)
  }

  const { findings = [], packages = [], dast_findings = [], project_path = '', user_familiarity = 1 } = body

  // Clamp familiarity to valid range (0 = executive, 1 = tech lead, 2 = security engineer)
  const familiarity = Math.max(0, Math.min(2, Math.round(user_familiarity)))

  // Cache keyed by a hash of the findings + packages + familiarity
  const inputHash = computeHash({ findings, packages, dast_findings, familiarity })
  console.log(`threat-lab: user=${user.id} hash=${inputHash} findings=${findings.length} packages=${packages.length} familiarity=${familiarity}`)

  const cached = await getFromCache(user.id, inputHash)
  if (cached) {
    console.log('threat-lab: cache hit')
    return json(cached)
  }

  const anthropicKey = Deno.env.get('ANTHROPIC_API_KEY')
  if (!anthropicKey) {
    console.error('threat-lab: ANTHROPIC_API_KEY not set')
    return json({ error: 'Service misconfigured' }, 500)
  }

  // Build prompt
  const prompt = buildPrompt(project_path, findings, packages, dast_findings)

  // System prompt varies by report audience level — controls tone and depth
  // of the stakeholder-facing report, independent of the user's own background.
  const familiarityInstruction = familiarity === 0
    ? `The report audience is EXECUTIVE / NON-TECHNICAL STAKEHOLDERS (investors, board members, non-technical co-founders).
- Write all descriptions, verdicts, and risk summaries in plain English — no jargon, no acronyms (or define them immediately).
- Focus on business impact: data breaches, downtime, regulatory fines, customer trust.
- Use simple analogies where helpful. Avoid terms like "SQL injection", "XSS", "SAST" — instead say "an attacker could read your customer database" or "malicious code could run in your users' browsers".
- Priority fix descriptions must say what to do in one sentence, not how to do it technically.
- This report will be shared externally — write it as a professional assessment, not a personal note.`
    : familiarity === 2
    ? `The report audience is SECURITY ENGINEERS or AUDITORS performing due diligence.
- Use full technical depth: CVE IDs, OWASP categories, CWE numbers, CVSS scores where relevant.
- Descriptions should be precise and actionable: file paths, function names, exploit chains.
- Priority fixes should include exact commands, config flags, or code patterns.
- Assume deep familiarity with SAST, DAST, dependency management, and common vulnerability classes.
- This report will be shared with technical stakeholders — write it as a professional security assessment.`
    : `The report audience is TECHNICAL LEADS or PRODUCT MANAGERS with moderate security knowledge.
- Use moderate technical depth: explain security terms briefly on first use.
- Balance business impact with technical remediation steps.
- Priority fixes should name the file/package and explain the "why" before the "how".
- This report will be shared with stakeholders — write it as a professional assessment.`

  const systemPrompt = `You are a senior application security engineer performing threat modelling on a real codebase.
You will receive SAST findings, dependency vulnerabilities, and optionally DAST findings.
Respond with a single JSON object matching the ThreatLabResult schema — no markdown, no code fences, no text outside the JSON.

${familiarityInstruction}`

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
        max_tokens: 4096,
        system: systemPrompt,
        messages: [{ role: 'user', content: prompt }],
      }),
    })
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err)
    console.error('Anthropic fetch failed:', msg)
    return json({ error: `Anthropic request failed: ${msg}` }, 500)
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
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err)
    console.error('threat-lab: failed to parse Anthropic response as JSON:', msg)
    return json({ error: 'AI service returned an unexpected response' }, 500)
  }
  const raw: string = completion.content?.[0]?.text ?? ''
  const text = raw.replace(/^```(?:json)?\s*/i, '').replace(/\s*```\s*$/, '').trim()

  let result: ThreatLabResult
  try {
    result = JSON.parse(text) as ThreatLabResult
    result.threat_index = Number(result.threat_index)
    if (isNaN(result.threat_index) || !result.grade || !result.verdict) {
      throw new Error('Missing required fields in response')
    }
    // Clamp threat_index
    result.threat_index = Math.max(0, Math.min(100, result.threat_index))
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err)
    console.error('threat-lab: parse failed:', msg, '\nRaw:', raw.slice(0, 500))
    return json({ error: `Failed to parse AI response: ${msg}` }, 500)
  }

  await saveToCache(user.id, inputHash, result)

  // Increment rate limit
  await supabase.from('ai_rate_limit').upsert({
    user_id: user.id,
    date: today,
    count: (limitRow?.count ?? 0) + 1,
  }, { onConflict: 'user_id,date' })

  console.log(`threat-lab: done threat_index=${result.threat_index} grade=${result.grade}`)
  return json(result)
}

// ── Prompt builder ─────────────────────────────────────────────────────────

function buildPrompt(
  projectPath: string,
  findings: Finding[],
  packages: Package[],
  dastFindings: Finding[],
): string {
  const severityOrder: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 }
  const sortedFindings = [...findings].sort((a, b) =>
    (severityOrder[a.Severity] ?? 4) - (severityOrder[b.Severity] ?? 4)
  )
  const sortedPkgs = [...packages]
    .filter(p => p.cve_count > 0)
    .sort((a, b) => (severityOrder[a.highest_severity ?? ''] ?? 4) -
      (severityOrder[b.highest_severity ?? ''] ?? 4))

  const findingLines = sortedFindings.slice(0, 50).map(f =>
    `[${(f.Severity ?? 'unknown').toUpperCase()}] ${f.Title} (${f.Scanner})${f.FilePath ? ` @ ${f.FilePath}:${f.LineNumber ?? ''}` : ''}`
  ).join('\n')

  const pkgLines = sortedPkgs.slice(0, 30).map(p => {
    const cves = p.advisories?.slice(0, 3).map(a => a.id).join(', ') ?? ''
    return `${p.name}@${p.version} (${p.ecosystem}) — ${p.cve_count} CVE(s), highest=${p.highest_severity ?? 'unknown'}${cves ? `, CVEs: ${cves}` : ''}${p.fix_version ? `, fix=${p.fix_version}` : ''}`
  }).join('\n')

  const dastLines = dastFindings.slice(0, 20).map(f =>
    `[DAST][${(f.Severity ?? 'unknown').toUpperCase()}] ${f.Title}`
  ).join('\n')

  return `Project: ${projectPath || 'unknown'}

## SAST Findings (${findings.length} total, showing top ${Math.min(50, findings.length)})
${findingLines || 'No SAST findings'}

## Vulnerable Dependencies (${packages.filter(p => p.cve_count > 0).length} packages with CVEs, showing top ${Math.min(30, sortedPkgs.length)})
${pkgLines || 'No vulnerable dependencies'}

${dastFindings.length > 0 ? `## DAST Findings (${dastFindings.length} total)\n${dastLines}` : ''}

Respond with ONLY a JSON object matching this exact schema:
{
  "threat_index": <0-100, where 0=perfect and 100=critically exposed>,
  "grade": <"A"|"B"|"C"|"D"|"F">,
  "verdict": "<1-2 sentence executive summary of the overall security posture>",
  "attack_vectors": [
    {
      "title": "<attack scenario name>",
      "severity": "<critical|high|medium|low>",
      "description": "<how an attacker would exploit this, in 2-3 sentences>",
      "findings_involved": ["<finding title or package name>"],
      "exploitability": "<easy|moderate|hard>"
    }
  ],
  "priority_fixes": [
    {
      "rank": <1-based integer>,
      "type": "<code|package|config>",
      "title": "<short action title>",
      "description": "<what to fix and why>",
      "command": "<npm/pip/go get command if type=package, else omit>",
      "file": "<relative file path if type=code, else omit>",
      "line": <line number if type=code, else omit>,
      "finding_id": "<finding ID if applicable, else omit>"
    }
  ],
  "compliance_summary": "<1-2 sentences covering OWASP Top 10 and CWE coverage of the findings>",
  "key_risks": ["<risk 1>", "<risk 2>", "<risk 3>"]
}

Rules:
- threat_index: base on severity distribution. All critical = ~90+. No findings = 5-15.
- grade: A=0-19, B=20-39, C=40-59, D=60-74, F=75-100
- attack_vectors: list 2-5 realistic attack chains, combining related findings
- priority_fixes: list top 5-8 fixes ordered by impact. Package fixes MUST include the install command.
- key_risks: exactly 3-5 concise bullet points
- No markdown, no code fences, raw JSON only`
}

// ── Cache helpers ──────────────────────────────────────────────────────────

async function getFromCache(userId: string, inputHash: string): Promise<ThreatLabResult | null> {
  const { data, error } = await supabase
    .from('threat_lab_cache')
    .select('result, created_at')
    .eq('user_id', userId)
    .eq('input_hash', inputHash)
    .single()

  if (error && error.code !== 'PGRST116') {
    console.error('threat-lab: cache read error:', error.message)
  }
  if (!data) return null

  const age = Date.now() - new Date(data.created_at as string).getTime()
  if (age > CACHE_TTL_MS) return null

  return data.result as ThreatLabResult
}

async function saveToCache(userId: string, inputHash: string, result: ThreatLabResult): Promise<void> {
  const { error } = await supabase.from('threat_lab_cache').upsert({
    user_id: userId,
    input_hash: inputHash,
    result,
  }, { onConflict: 'user_id,input_hash' })
  if (error) console.error('threat-lab: cache write error:', error.message)
}

// ── Utilities ──────────────────────────────────────────────────────────────

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
