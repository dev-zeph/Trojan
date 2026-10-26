import { validateToken, corsHeaders } from '../_shared/auth.ts'
import { supabase } from '../_shared/supabase.ts'
import { parseBody } from '../_shared/body.ts'

// Code-RAG embedding endpoint (docs/trojan-agentic-implementation.md §4). Takes a
// batch of chunk texts (source code, or a triage query) and returns one embedding
// vector per input, in order. The embeddings key lives here — server-side only —
// exactly like triage/synthesize; the Go binary never holds it.
//
// Provider is behind EMBED_MODEL/EMBED_PROVIDER env vars (default Voyage
// voyage-code-3) so switching is config, not a redeploy of the client.
//
// Bodies are base64-wrapped by the client ({ encoded }) so Cloudflare's WAF
// doesn't 403 on source that contains attack signatures — see _shared/body.ts.

interface EmbedRequest {
  texts?: string[]
  inputType?: 'document' | 'query' // Voyage distinguishes indexed docs from search queries
}

const DAILY_LIMIT = 100      // shared ai_rate_limit bucket, mirrors triage/synthesize
const MAX_TEXTS = 128        // Voyage caps inputs per request

Deno.serve(async (req) => {
  if (req.method === 'OPTIONS') return json(null, 200, corsHeaders())
  if (req.method !== 'POST') return json({ error: 'Method not allowed' }, 405)

  const token = req.headers.get('authorization')?.replace('Bearer ', '')
  if (!token) return json({ error: 'Unauthorized' }, 401)

  const user = await validateToken(token)
  if (!user) return json({ error: 'Unauthorized' }, 401)
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

  let body: EmbedRequest
  try {
    body = await parseBody<EmbedRequest>(req)
  } catch {
    return json({ error: 'Invalid JSON body' }, 400)
  }

  const texts = (body.texts ?? []).slice(0, MAX_TEXTS)
  if (texts.length === 0) return json({ embeddings: [] })

  const voyageKey = Deno.env.get('VOYAGE_API_KEY')
  if (!voyageKey) {
    console.error('embed: VOYAGE_API_KEY not set')
    return json({ error: 'Service misconfigured' }, 500)
  }
  const model = Deno.env.get('EMBED_MODEL') ?? 'voyage-code-3'
  const inputType = body.inputType === 'query' ? 'query' : 'document'

  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), 45_000)

  let resp: Response
  try {
    resp = await fetch('https://api.voyageai.com/v1/embeddings', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${voyageKey}`,
        'content-type': 'application/json',
      },
      signal: controller.signal,
      body: JSON.stringify({ input: texts, model, input_type: inputType }),
    })
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err)
    console.error('embed: Voyage fetch failed:', msg)
    return json({ error: `Embedding service error: ${msg}` }, 500)
  } finally {
    clearTimeout(timer)
  }

  if (!resp.ok) {
    const errBody = await resp.text().catch(() => '')
    console.error(`embed: Voyage API error ${resp.status}:`, errBody)
    return json({ error: `Embedding service error (${resp.status})` }, 500)
  }

  let embeddings: number[][]
  try {
    const parsed = await resp.json() as { data?: { embedding: number[]; index: number }[] }
    const data = parsed.data ?? []
    // Order by index so embeddings[i] corresponds to texts[i].
    data.sort((a, b) => a.index - b.index)
    embeddings = data.map(d => d.embedding)
    if (embeddings.length !== texts.length) {
      throw new Error(`expected ${texts.length} embeddings, got ${embeddings.length}`)
    }
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err)
    console.error('embed: parse failed:', msg)
    return json({ error: `Failed to embed: ${msg}` }, 500)
  }

  await supabase.from('ai_rate_limit').upsert({
    user_id: user.id,
    date: today,
    count: (limitRow?.count ?? 0) + 1,
  }, { onConflict: 'user_id,date' })

  return json({ embeddings })
})

function json(data: unknown, status = 200, extraHeaders: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...corsHeaders(), 'Content-Type': 'application/json', ...extraHeaders },
  })
}
