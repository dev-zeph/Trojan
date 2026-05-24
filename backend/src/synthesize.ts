import Anthropic from '@anthropic-ai/sdk'
import { supabase } from './supabase.ts'

// Finding metadata sent from the CLI — never includes source code
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

// Synthesize uses Claude to generate plain-English explanation and fix steps.
// Results are cached in Supabase by ruleId to avoid redundant API calls.
export async function synthesize(
  finding: FindingMeta,
  anthropicKey: string // platform key, managed centrally
): Promise<Synthesis> {
  // Check cache first
  const cached = await getFromCache(finding.ruleId, finding.scanner)
  if (cached) return cached

  const client = new Anthropic({ apiKey: anthropicKey })

  const prompt = `You are a security expert helping a developer understand and fix a vulnerability found in their code.

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

  const message = await client.messages.create({
    model: 'claude-haiku-4-5-20251001',
    max_tokens: 1024,
    messages: [{ role: 'user', content: prompt }],
  })

  const text = message.content[0]?.type === 'text' ? message.content[0].text : '{}'

  let synthesis: Synthesis
  try {
    synthesis = JSON.parse(text) as Synthesis
  } catch {
    synthesis = {
      simply: finding.rawMessage,
      actions: ['Review the flagged code and apply the recommended fix from the scanner documentation.'],
    }
  }

  // Cache the result
  await saveToCache(finding.ruleId, finding.scanner, synthesis)

  return synthesis
}

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
