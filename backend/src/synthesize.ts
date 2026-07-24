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
  familiarity?: number  // 0 = non-technical, 1 = junior dev, 2 = experienced
  aboutYou?: string     // free-form user context
}

interface Synthesis {
  simply: string
  actions: string[]
}

const TONE_INSTRUCTIONS: Record<number, string> = {
  0: `The user is a non-technical founder or business person. Use plain, everyday language — no jargon, no code terms, no acronyms. Explain what the risk means for their business, customers, and data. Focus on impact, not implementation. Keep it short and clear.`,
  1: `The user is a junior developer with limited security experience. Use simple language, explain security terms when you first use them, and avoid dense technical jargon. Give practical, step-by-step instructions they can follow without deep security knowledge.`,
  2: `The user is an experienced developer comfortable with security concepts. Be concise and technical — use standard security terminology, reference CWEs/CVEs where relevant, and assume they understand code patterns and frameworks.`,
}

// Synthesize uses Claude to generate plain-English explanation and fix steps.
// Results are cached in Supabase by ruleId to avoid redundant API calls.
export async function synthesize(
  finding: FindingMeta,
  anthropicKey: string // platform key, managed centrally
): Promise<Synthesis> {
  // Check cache first — include familiarity in the cache key so tone changes regenerate
  const cacheKey = `${finding.ruleId}:${finding.scanner}:${finding.familiarity ?? 1}`
  const cached = await getFromCache(finding.ruleId, finding.scanner, finding.familiarity ?? 1)
  if (cached) return cached

  const client = new Anthropic({ apiKey: anthropicKey })

  const famLevel = finding.familiarity ?? 1
  const toneInstruction = TONE_INSTRUCTIONS[famLevel] ?? TONE_INSTRUCTIONS[1]
  const userContext = finding.aboutYou
    ? `\n\nAdditional context about the user:\n${finding.aboutYou}`
    : ''

  const prompt = `You are a security expert explaining a vulnerability to a specific user.

${toneInstruction}${userContext}

Finding:
- Title: ${finding.title}
- Scanner: ${finding.scanner}
- Category: ${finding.category}
- Severity: ${finding.severity}
- Rule: ${finding.ruleId}
- Description: ${finding.rawMessage}

Respond with a JSON object with exactly two fields:
1. "simply": A 2-3 sentence explanation of what this vulnerability means. Tailor the language and depth to the user profile above.
2. "actions": An array of 3-5 short, specific, actionable steps to fix this vulnerability. Each step should be one sentence. Match the technical level to the user profile.

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

  // Cache the result — keyed by familiarity so tone changes get fresh responses
  await saveToCache(finding.ruleId, finding.scanner, famLevel, synthesis)

  return synthesis
}

async function getFromCache(ruleId: string, scanner: string, familiarity: number): Promise<Synthesis | null> {
  const { data } = await supabase
    .from('ai_cache')
    .select('simply, actions')
    .eq('rule_id', ruleId)
    .eq('scanner', scanner)
    .eq('familiarity', familiarity)
    .single()

  if (!data) return null
  return { simply: data.simply as string, actions: data.actions as string[] }
}

async function saveToCache(ruleId: string, scanner: string, familiarity: number, synthesis: Synthesis): Promise<void> {
  await supabase.from('ai_cache').upsert({
    rule_id: ruleId,
    scanner,
    familiarity,
    simply: synthesis.simply,
    actions: synthesis.actions,
  })
}
