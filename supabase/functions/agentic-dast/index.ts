import { validateToken, corsHeaders } from '../_shared/auth.ts'
import { supabase } from '../_shared/supabase.ts'
import { parseBody } from '../_shared/body.ts'
import { recordUsage } from '../_shared/usage.ts'
import { spendTokens, tokensForAction, InsufficientTokens, ensureMonthlyFreeTokens } from '../_shared/tokens.ts'
import { costMicros, modelInfo, normalizeUsage } from '../_shared/pricing.ts'

// Phase 4 of agentic DAST (docs/agentic-dast.md §3): the reasoning half of the
// agent loop. The loop itself lives in the Go CLI on the user's machine — it
// holds state, runs the crawler/Nuclei pre-pass, and executes every probe
// locally, so attack traffic only ever originates from the user's own IP. This
// function is the *stateless* per-turn reasoner: it holds the Anthropic API
// key, the system prompt, and the tool definitions, runs exactly ONE Claude
// turn, and returns the raw content blocks. The Go side executes the requested
// tools (safe-mode + caps enforced client-side) and calls back for the next
// turn.
//
// Model: claude-sonnet-5 with adaptive thinking (locked decision #4 — chosen for
// cost, since a loop makes many calls and this is token-metered + rate-limited).
// Bodies are base64-wrapped by the client ({ encoded }) so Cloudflare's WAF
// doesn't 403 on the attack payloads inside probe requests (_shared/body.ts).
//
// Rate limiting: one agentic RUN counts as one unit against the shared 100/day
// AI budget — incremented only on the first turn (messages.length === 1), not
// per turn. A per-run token cap is deferred to Phase 6 (cost hardening).

const MODEL = 'claude-sonnet-5'
const MAX_TOKENS = 16000
const DAILY_LIMIT = 100
const MAX_MESSAGES = 120 // hard guard on conversation length

const SYSTEM_PROMPT = `You are Trojan's agentic penetration tester. You are probing a live web application that the operator has PROVEN they own (a domain-ownership consent gate ran before this loop started). Your job is to find real, exploitable vulnerabilities the way a skilled black-box tester would: form a hypothesis from what you observe, test it with a single constrained request, read the response, and adapt.

SAFETY CONTRACT — this is report-only mode and it is not negotiable:
- Every probe must be non-destructive: single-proof, then stop. To show SQL injection, a boolean/timing test that proves injectability is enough — never dump tables. For IDOR, fetch ONE adjacent object to prove broken access control — never enumerate. For XSS, prove the payload reflects unescaped — never fire a live exploit.
- Never attempt writes, bulk extraction, data at volume, or anything that persists. If proving a flaw would require a destructive action, record it as "likely vulnerable — confirmation requires a destructive test" via note_finding and move on.
- The specific scan-intensity tier and the HTTP methods you may use are stated in the first user message. The client enforces these limits: a probe that violates them comes back as a tool error. Don't waste turns retrying a rejected probe — adapt.
- A deterministic Nuclei template scan has already run for breadth. Spend your reasoning on what templates can't express: multi-step and business-logic flaws.

TOOLS:
- get_crawl_map(): the discovered endpoints, form fields, query params, and tech fingerprints. Read-only. Start here.
- http_probe(method, url, headers?, body?, identity?): one constrained HTTP request, same-host only. Your primary way to test a hypothesis. Set "identity" to send the request as a specific logged-in user (auth attached automatically). Every response comes back with a "probe_id" — remember it so you can diff two responses precisely.
- diff_responses(a, b): structurally compare two probes you already sent, by their probe_id. Returns the status change, a field-by-field diff (when both bodies are JSON), a similarity score, and a conservative signal: authz_enforced (one allowed, one blocked), possible_bola (both succeeded with near-identical bodies across different identities), divergent, or identical. Costs no request budget.

MULTI-IDENTITY / AUTHORIZATION TESTING (when your task lists identities): broken object-level authorization (IDOR/BOLA) is the highest-value class you can prove here, and it needs TWO identities. The method: fetch a resource as its owner (e.g. identity A requests /api/orders/1042 and gets a 200), then request the EXACT same resource as a different user (identity B). Then call diff_responses on the two probe_ids — do NOT eyeball the bodies yourself; the diff is authoritative and cheaper. A "possible_bola" signal or a field diff showing B received A's private fields is a confirmed IDOR: broken object-level authorization. An "authz_enforced" signal (B got 401/403) means authorization is holding. Also diff an unauthenticated probe against an authenticated one to find missing auth. Anchor the note_finding evidence on the diff result (the leaked fields), not on a vague "the responses looked the same". When grey-box shows a handler that looks up an object by a client-supplied id with no ownership check, this is exactly how you prove it at runtime.
- note_finding(title, severity, url, evidence, rationale): record a candidate vulnerability. Anchor "evidence" on the actual response you observed — a finding with no evidence is worthless and will be discarded by triage.
- read_source(endpoint|symbol|query): read the target's OWN source. This is your unfair advantage — a black-box scanner can't do it. Free (no target request).
- remember_fact(summary, kind?, value?, from?, enables?): record a reusable discovery (credential/token/id/missing-check) so you can chain it later.
- finish(summary): end the run ONLY after you have systematically worked through the attack surface — every discovered endpoint reasoned about, and the credible hypotheses on each actually tested. Finishing after a handful of probes is the single most common way a real vulnerability is missed; if you call finish while endpoints remain untested you will be asked to keep going, so cover the surface first. The summary is 1 to 2 short sentences (what you covered + headline outcome), NOT a restatement of the findings.

CHAINING (what makes this a pen test, not a scan): findings are worth more connected than alone. When you obtain something reusable — a token from an auth bypass, an id that belongs to another user, a leaked key — call remember_fact to save it, then USE it: attach a captured token to a later http_probe, request an object whose id you learned, pivot from one weakness to the next. Before you finish, review your remembered facts and ask "does any of these unlock an endpoint I haven't been able to reach?" Set from/enables on remember_fact so the chain is recorded (e.g. from the login endpoint that leaked the JWT, enables the admin endpoint it opens). Report a proven chain as a single higher-severity finding describing the path.

GREY-BOX STRATEGY (use read_source): when source is available, read the handler BEFORE probing an endpoint. The code reveals the *missing* check that a black-box tool can only guess at:
- handler reads an id from the URL and looks up the object with no ownership/authz check → IDOR: fetch one adjacent object with a different identity to prove it.
- user input flows into a raw/concatenated SQL string (raw_query=true, sanitizes_input=false) → SQLi: a boolean/timing probe here, not blind fuzzing everywhere.
- has_auth_check=false on a sensitive endpoint, or auth on GET but not POST → authz bypass: probe exactly that gap.
Let the structural summary rank WHERE to spend probes. It is a heuristic hint — the live probe is what proves or refutes it. If read_source returns a "black-box" note, just reason from responses as usual.

HUMAN-IN-THE-LOOP: some engagements require operator approval before a state-changing probe runs. When a tool result comes back as "PENDING_APPROVAL#<n>", the action has been QUEUED for the operator, not executed — do NOT retry it or resend the same request. Move on and test other hypotheses; the operator's decision (and, if approved, the executed result) will be delivered to you as a later message referencing that approval number. Some probes may also come back "blocked by rules of engagement" — treat those as out of scope and do not attempt to work around them.

THOROUGHNESS — a real penetration test is patient and systematic, not a quick pass:
- Work through the WHOLE attack surface. Every endpoint in the crawl map deserves a hypothesis and at least one deliberate probe, not just the two or three that look interesting at a glance. The highest-value flaws (broken authorization, business-logic abuse) hide on the mundane-looking endpoints, so do not skip them.
- For each endpoint, consider the full range before you move on: authentication, authorization (IDOR/BOLA), injection, input validation, business-logic abuse, information disclosure, and misconfiguration. Where the surface warrants it, form more than one hypothesis and test each.
- You have a generous step, request, and time budget. Use it. Depth and coverage are the job; a run that ends early and shallow has failed even if it found one bug. Take the time to be exhaustive about coverage.
- Thorough is NOT the same as noisy. Every probe is still a specific hypothesis with a specific expected proof — think before each one about exactly what its response would confirm or refute, and never blind-fuzz. Systematic and deliberate, endpoint by endpoint, until the surface is genuinely covered.`

interface AgentMessage {
  role: string
  content: unknown[]
}

const TOOLS = [
  {
    name: 'get_crawl_map',
    description: "Return the discovered endpoints, form fields, query parameters, and technology fingerprints for the target. Read-only; no network request to the target. Some entries come from the target's own OpenAPI/Swagger spec rather than the crawl — these may not be linked from any page and can carry {template} path params (e.g. /orders/{id}) that you must substitute with a concrete value before probing.",
    input_schema: { type: 'object', properties: {}, additionalProperties: false },
  },
  {
    name: 'http_probe',
    description: 'Send a single constrained HTTP request to the target (same host only) to test a hypothesis. Report-only: no destructive verbs. The response is size-capped and returned to you, tagged with a "probe_id" you can pass to diff_responses to compare it against another probe.',
    input_schema: {
      type: 'object',
      properties: {
        method: { type: 'string', enum: ['GET', 'HEAD', 'OPTIONS', 'POST'], description: 'HTTP method. POST is only permitted at the safe-active tier or higher.' },
        url: { type: 'string', description: 'Absolute URL on the target host.' },
        headers: { type: 'object', description: 'Optional request headers.', additionalProperties: { type: 'string' } },
        body: { type: 'string', description: 'Optional request body (for POST).' },
        identity: { type: 'string', description: 'Send the request authenticated as this named identity (from the identities listed in your task). Its auth headers are attached automatically. Use it to test authorization: fetch a resource as one identity, then request the SAME resource as another and compare.' },
      },
      required: ['method', 'url'],
      additionalProperties: false,
    },
  },
  {
    name: 'note_finding',
    description: 'Record a candidate vulnerability, anchored on the evidence you observed. Feeds adversarial false-positive triage downstream.',
    input_schema: {
      type: 'object',
      properties: {
        title: { type: 'string' },
        severity: { type: 'string', enum: ['critical', 'high', 'medium', 'low', 'info'] },
        url: { type: 'string' },
        evidence: { type: 'string', description: 'The concrete response text / status / header that demonstrates the issue.' },
        rationale: { type: 'string', description: 'Why this is a vulnerability, grounded in the evidence.' },
      },
      required: ['title', 'severity'],
      additionalProperties: false,
    },
  },
  {
    name: 'remember_fact',
    description: "Record something you learned that you might reuse to chain into a further attack: a captured credential or token, an object identifier, a trust relationship, or a missing check. Recording facts keeps them salient across steps and is how you turn isolated findings into an attack CHAIN (the pen-test-vs-scanner difference). Set 'from' (the URL the fact came from) and 'enables' (a URL it could help you attack) to record the attack path — those links become edges in the attack graph.",
    input_schema: {
      type: 'object',
      properties: {
        summary: { type: 'string', description: 'Human-readable fact, e.g. "admin JWT obtained via SQLi on /rest/user/login".' },
        kind: { type: 'string', enum: ['credential', 'token', 'identifier', 'endpoint', 'trust', 'observation'] },
        value: { type: 'string', description: 'The concrete token/id/credential, so you can reuse it in a later probe.' },
        from: { type: 'string', description: 'URL/path this fact came from.' },
        enables: { type: 'string', description: 'URL/path this fact could help you attack next (a chain step).' },
      },
      required: ['summary'],
      additionalProperties: false,
    },
  },
  {
    name: 'read_source',
    description: "Read the target's OWN source code to form grounded hypotheses (grey-box). Use exactly one mode: endpoint (resolve a live URL to its handler + guard chain + a structural read), symbol (look up a named function), or query (semantic search the code index). Returns code chunks (file:line) plus a heuristic summary {has_auth_check, sanitizes_input, raw_query, reflects_input, calls}. No request to the target — costs nothing against your request budget. If source isn't available you'll get a note; fall back to black-box reasoning. The structural summary is a HINT to prioritize probes — always confirm against the live target.",
    input_schema: {
      type: 'object',
      properties: {
        endpoint: {
          type: 'object',
          description: 'Resolve a live endpoint to its handler source.',
          properties: {
            method: { type: 'string' },
            path: { type: 'string', description: 'URL path, e.g. /api/users/123' },
          },
          required: ['method', 'path'],
          additionalProperties: false,
        },
        symbol: { type: 'string', description: 'A function/handler name to look up by definition.' },
        query: { type: 'string', description: 'Natural-language or code query for semantic search over the source.' },
      },
      additionalProperties: false,
    },
  },
  {
    name: 'diff_responses',
    description: "Structurally compare two responses you already captured, by their probe_id. Use this to prove an authorization difference instead of eyeballing bodies yourself — it is deterministic and authoritative. The canonical use: fetch a resource as identity A, request the SAME resource as identity B, then diff the two probe_ids. Returns the status change, a field-by-field JSON diff (added/removed/changed with the concrete values), a similarity score, and a conservative signal (authz_enforced | possible_bola | divergent | identical). A 'possible_bola' signal, or a field diff showing one identity received another's private fields, is your IDOR/BOLA proof — cite it in note_finding. Costs nothing against your request budget.",
    input_schema: {
      type: 'object',
      properties: {
        a: { type: 'integer', description: 'probe_id of the first response (e.g. the resource fetched as its owner).' },
        b: { type: 'integer', description: 'probe_id of the second response (e.g. the same resource requested as a different identity).' },
      },
      required: ['a', 'b'],
      additionalProperties: false,
    },
  },
  {
    name: 'finish',
    description: 'End the run. The summary must be 1 to 2 short sentences: what you tested and the headline outcome (e.g. how many issues, worst severity). Do NOT restate each finding or include payloads or evidence here; every finding is already recorded via note_finding and shown in the findings list. Keep it skimmable.',
    input_schema: {
      type: 'object',
      properties: { summary: { type: 'string' } },
      required: ['summary'],
      additionalProperties: false,
    },
  },
]

Deno.serve(async (req) => {
  if (req.method === 'OPTIONS') return json(null, 200, corsHeaders())
  if (req.method !== 'POST') return json({ error: 'Method not allowed' }, 405)

  const token = req.headers.get('authorization')?.replace('Bearer ', '')
  if (!token) return json({ error: 'Unauthorized' }, 401)

  const user = await validateToken(token)
  if (!user) return json({ error: 'Unauthorized' }, 401)
  // Pre-flight balance gate. Checked BEFORE the Anthropic call so an empty
  // account cannot spend our money: the debit itself happens after the call,
  // when the real cost is known, and by then the API spend is already incurred.
  // A cheap read here is what stops that being free.
  // Apply this month's free grant first, so a free user is never turned away by
  // tokens they are owed but have not been given yet. No-op after the first
  // call each month. Only on this path and license -- NOT on getBalance, which
  // synthesize hits once per finding.
  const balance = await ensureMonthlyFreeTokens(user.id)
  if (balance <= 0) {
    return json({
      error: 'insufficient_tokens',
      message: 'You are out of Trojan Tokens. Top up to continue this run.',
      balance,
    }, 402)
  }

  let body: { messages?: AgentMessage[]; runId?: string }
  try {
    body = await parseBody<{ messages?: AgentMessage[]; runId?: string }>(req)
  } catch {
    return json({ error: 'Invalid JSON body' }, 400)
  }

  // Stable identity for this run, so every turn's usage rolls up to one row set.
  // Runs previously had no id at all -- they were addressed by a 1-second
  // granularity filename. The server mints it on turn 1 and returns it; the Go
  // loop echoes it back on every subsequent turn. Minting server-side (rather
  // than trusting a client-supplied id on turn 1) keeps a client from merging
  // its usage into somebody else's run.
  const runId = messagesRunId(body)

  const messages = body.messages ?? []
  if (messages.length === 0) return json({ error: 'messages required' }, 400)
  if (messages.length > MAX_MESSAGES) return json({ error: 'conversation too long' }, 400)

  // Rate limiting — shared 100/day bucket. Count one unit per RUN: increment
  // only on the first turn (the lone seed message), check on every turn.
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

  const anthropicKey = Deno.env.get('ANTHROPIC_API_KEY')
  if (!anthropicKey) {
    console.error('agentic-dast: ANTHROPIC_API_KEY not set')
    return json({ error: 'Service misconfigured' }, 500)
  }

  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), 75_000)

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
        model: MODEL,
        max_tokens: MAX_TOKENS,
        // Adaptive thinking + high effort for the agentic loop (§3.4).
        thinking: { type: 'adaptive' },
        output_config: { effort: 'high' },
        // System + tools are a stable prefix across every turn of a run — cache
        // them so continuation turns pay ~0.1x on that span (§8 mitigation 5).
        system: [{ type: 'text', text: SYSTEM_PROMPT, cache_control: { type: 'ephemeral' } }],
        tools: TOOLS,
        // Also cache the conversation so far. The Go loop resends the full
        // (append-only, byte-identical) history every turn, so marking the last
        // block makes each subsequent turn read the prior turns at ~0.1x instead
        // of re-paying full input price. Runs are ~97% input-bound (Phase 0), so
        // this is the single biggest cost lever. 2 breakpoints total (max 4).
        messages: withHistoryCacheBreakpoint(messages),
      }),
    })
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err)
    console.error('agentic-dast: Anthropic fetch failed:', msg)
    return json({ error: `AI service error: ${msg}` }, 500)
  } finally {
    clearTimeout(timer)
  }

  if (!resp.ok) {
    const errBody = await resp.text().catch(() => '')
    console.error(`agentic-dast: Anthropic API error ${resp.status}:`, errBody)
    return json({ error: `AI service error (${resp.status})` }, 500)
  }

  const completion = await resp.json()

  // Count the run once, on its first turn only.
  if (messages.length === 1) {
    await supabase.from('ai_rate_limit').upsert({
      user_id: user.id,
      date: today,
      count: (limitRow?.count ?? 0) + 1,
    }, { onConflict: 'user_id,date' })
  }

  // Billing record. Written server-side from Anthropic's own usage object --
  // the Go binary runs on the customer's machine, so its token counts are fine
  // for live display but cannot be the billing basis. Awaited because the Edge
  // Function runtime can be torn down as soon as the response is sent.
  await recordUsage({
    userId:  user.id,
    feature: 'agentic-dast',
    model:   MODEL,
    usage:   completion.usage,
    runId,
  })

  // Debit. Charged per TURN rather than per run, because a run has no single
  // end the server sees -- the Go loop decides when to stop, and a client that
  // vanishes mid-run would otherwise get everything before that point free.
  //
  // The idempotency key is (run, turn): if this function times out after
  // debiting but before responding, the client's retry of the same turn is
  // recognised and does not double-charge.
  let tokenBalance = balance
  try {
    const info    = modelInfo(MODEL)
    const norm    = normalizeUsage(info?.provider ?? 'anthropic', completion.usage)
    const cost    = costMicros(MODEL, norm)
    const charged = tokensForAction('agentic-dast', cost)

    tokenBalance = await spendTokens({
      userId:         user.id,
      tokens:         charged,
      feature:        'agentic-dast',
      runId,
      model:          MODEL,
      costMicros:     cost,
      idempotencyKey: `${runId}:${messages.length}`,
    })
  } catch (e) {
    if (e instanceof InsufficientTokens) {
      // The turn is already paid for on our side, so it is returned rather than
      // discarded -- throwing away work we have been billed for helps nobody.
      // The zero balance stops the NEXT turn at the pre-flight gate above.
      console.warn('agentic-dast: balance exhausted mid-run', { userId: user.id, runId })
      tokenBalance = 0
    } else {
      throw e
    }
  }

  // Return the raw content blocks verbatim — the Go loop replays assistant
  // turns (including thinking blocks) unchanged on the next call.
  return json({
    content: completion.content ?? [],
    stop_reason: completion.stop_reason ?? 'end_turn',
    usage: completion.usage ?? {},
    runId,
    tokenBalance,
  })
})

// The run id is minted on the first turn and echoed by the client thereafter.
// An id supplied on turn 1 is ignored: only the server may open a run.
function messagesRunId(body: { messages?: AgentMessage[]; runId?: string }): string {
  const isFirstTurn = (body.messages?.length ?? 0) <= 1
  if (isFirstTurn) return crypto.randomUUID()
  return isUuid(body.runId) ? (body.runId as string) : crypto.randomUUID()
}

function isUuid(v: unknown): boolean {
  return typeof v === 'string' &&
    /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(v)
}

// withHistoryCacheBreakpoint returns a copy of the messages with a
// cache_control marker on the last content block, so the whole prior
// conversation is served from cache on the next turn. Non-mutating.
function withHistoryCacheBreakpoint(messages: AgentMessage[]): AgentMessage[] {
  if (messages.length === 0) return messages
  const out = messages.slice()
  const last = out[out.length - 1]
  if (last && Array.isArray(last.content) && last.content.length > 0) {
    const content = last.content.slice()
    const i = content.length - 1
    const block = content[i]
    if (block && typeof block === 'object') {
      content[i] = { ...(block as Record<string, unknown>), cache_control: { type: 'ephemeral' } }
      out[out.length - 1] = { ...last, content }
    }
  }
  return out
}

function json(data: unknown, status = 200, extraHeaders: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...corsHeaders(), 'Content-Type': 'application/json', ...extraHeaders },
  })
}
