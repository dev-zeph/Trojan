import { validateToken, isPro, corsHeaders } from '../_shared/auth.ts'
import { supabase } from '../_shared/supabase.ts'

interface FindingMeta {
  ruleId: string
  scanner: string
  category: string
  severity: string
  title: string
  rawMessage: string
}

interface Synthesis {
  simply: string
  actions: string[]
}

Deno.serve(async (req) => {
  if (req.method === 'OPTIONS') {
    return new Response(null, { headers: corsHeaders() })
  }

  if (req.method !== 'POST') {
    return json({ error: 'Method not allowed' }, 405)
  }

  const token = req.headers.get('authorization')?.replace('Bearer ', '')
  if (!token) return json({ error: 'Unauthorized' }, 401)

  const user = await validateToken(token)
  if (!user) return json({ error: 'Unauthorized' }, 401)
  if (!isPro(user)) return json({ error: 'Pro subscription required' }, 403)

  const finding: FindingMeta = await req.json()

  // Check cache first — same finding never hits the API twice
  // Skip cache entries whose "simply" is identical to the raw scanner message (stale fallback data)
  const cached = await getFromCache(finding.ruleId, finding.scanner)
  if (cached && cached.simply !== finding.rawMessage) return json(cached)

  const deepseekKey = Deno.env.get('DEEPSEEK_API_KEY')
  if (!deepseekKey) return json({ error: 'Service misconfigured' }, 500)

  const userPrompt = `You are a security expert helping a developer understand and fix a vulnerability found in their code.

Finding:
- Title: ${finding.title}
- Scanner: ${finding.scanner}
- Category: ${finding.category}
- Severity: ${finding.severity}
- Rule: ${finding.ruleId}
- Description: ${finding.rawMessage}

Respond with a JSON object with exactly two fields:
1. "simply": A 2-3 sentence plain-English explanation of what this vulnerability means for the developer's application. Write as if explaining to a smart developer who is not a security expert. Mention real-world impact.
2. "actions": An array of 3-5 short, specific, actionable steps to fix this vulnerability. Each step should be one sentence. Be concrete, not vague.

Respond with only valid JSON. No markdown, no extra text.`

  const resp = await fetch('https://api.deepseek.com/v1/chat/completions', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${deepseekKey}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      model: 'deepseek-chat',
      max_tokens: 1024,
      messages: [
        { role: 'system', content: 'You are a security expert. Always respond with raw JSON only — no markdown, no code fences, no explanation outside the JSON object.' },
        { role: 'user', content: userPrompt },
      ],
    }),
  })

  if (!resp.ok) return json({ error: `DeepSeek API error (${resp.status})` }, 500)

  const completion = await resp.json()
  const raw: string = completion.choices?.[0]?.message?.content ?? ''

  // Strip markdown code fences if Claude wrapped the JSON
  const text = raw.replace(/^```(?:json)?\s*/i, '').replace(/\s*```\s*$/, '').trim()

  let synthesis: Synthesis
  try {
    const parsed = JSON.parse(text) as Synthesis
    if (!parsed.simply || !Array.isArray(parsed.actions)) throw new Error('unexpected shape')
    synthesis = parsed
  } catch {
    // Best-effort extraction: look for a "simply" value in the raw text
    const simplyMatch = raw.match(/"simply"\s*:\s*"((?:[^"\\]|\\.)*)"/s)
    const actionsMatch = [...raw.matchAll(/"([^"]{10,})"/g)]
      .map(m => m[1])
      .filter(s => s !== simplyMatch?.[1])
      .slice(0, 5)

    synthesis = {
      simply: simplyMatch?.[1]
        ? simplyMatch[1].replace(/\\n/g, ' ').replace(/\\"/g, '"')
        : `This is a ${finding.severity} severity ${finding.category} vulnerability (${finding.ruleId}). ${finding.rawMessage}`,
      actions: actionsMatch.length > 0
        ? actionsMatch
        : ['Review the flagged code carefully.', 'Consult the scanner documentation for the rule that triggered this finding.', 'Apply the recommended fix and re-run `trojan scan` to verify it is resolved.'],
    }
  }

  await saveToCache(finding.ruleId, finding.scanner, synthesis)

  return json(synthesis)
})

async function getFromCache(ruleId: string, scanner: string): Promise<Synthesis | null> {
  const { data } = await supabase
    .from('ai_cache')
    .select('simply, actions')
    .eq('rule_id', ruleId)
    .eq('scanner', scanner)
    .single()

  if (!data) return null
  return { simply: data.simply as string, actions: data.actions as string[] }
}

async function saveToCache(ruleId: string, scanner: string, synthesis: Synthesis): Promise<void> {
  await supabase.from('ai_cache').upsert({
    rule_id: ruleId,
    scanner,
    simply: synthesis.simply,
    actions: synthesis.actions,
  })
}

function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...corsHeaders(), 'Content-Type': 'application/json' },
  })
}
