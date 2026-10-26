import { supabase } from './supabase.ts'
import {
  costMicros, modelInfo, normalizeUsage,
  type Provider, type RawUsage, type TokenUsage,
} from './pricing.ts'

export interface RecordUsageArgs {
  userId: string
  feature: string
  /** Exact model id, so a later price change stays auditable against history. */
  model: string
  /** Raw provider usage object, passed through verbatim. Shape is resolved from
   *  the model's provider -- callers never normalize. */
  usage?: RawUsage
  /** Groups turns of one multi-turn agentic run. Omit for one-shot calls. */
  runId?: string | null
  /** Served from our own cache: zero provider spend, still recorded so hit rate
   *  stays measurable. */
  cacheHit?: boolean
  /** Only needed for a model absent from the price table. */
  provider?: Provider
}

const ZERO: TokenUsage = {
  inputTokens: 0, outputTokens: 0, cacheReadTokens: 0, cacheWriteTokens: 0,
}

/**
 * Append one row to the usage ledger.
 *
 * Deliberately never throws and never returns a failure. Metering must not be
 * able to break a customer's scan: a lost billing data point is recoverable, a
 * 500 here aborts work the user is waiting on. Failures are logged loudly
 * instead of vanishing the way the old `catch {}` blocks did.
 *
 * Callers should `await` this before returning -- an Edge Function's runtime can
 * be torn down as soon as the response is sent, so a floating promise may never
 * land.
 */
export async function recordUsage(args: RecordUsageArgs): Promise<void> {
  try {
    const cacheHit = args.cacheHit ?? false
    const info = modelInfo(args.model)
    const provider: Provider = info?.provider ?? args.provider ?? 'anthropic'

    if (!cacheHit && !info) {
      // Not fatal: the row is still written so token counts survive and can be
      // re-costed later. But it means _shared/pricing.ts is out of date with
      // what a function actually calls, which UNDERSTATES cost on every such
      // call -- so it has to be loud.
      console.error('usage: UNKNOWN MODEL -- cost recorded as 0, add it to _shared/pricing.ts', {
        model: args.model, feature: args.feature, assumedProvider: provider,
      })
    }

    const usage: TokenUsage = cacheHit ? ZERO : normalizeUsage(provider, args.usage)

    const { error } = await supabase.from('usage_events').insert({
      user_id:  args.userId,
      run_id:   args.runId ?? null,
      feature:  args.feature,
      provider,
      model:    args.model,
      input_tokens:                usage.inputTokens,
      output_tokens:               usage.outputTokens,
      cache_read_input_tokens:     usage.cacheReadTokens,
      cache_creation_input_tokens: usage.cacheWriteTokens,
      cost_micros: cacheHit ? 0 : costMicros(args.model, usage),
      cache_hit:   cacheHit,
    })

    if (error) {
      console.error('usage: ledger write failed', {
        feature: args.feature, userId: args.userId, error: error.message,
      })
    }
  } catch (e) {
    console.error('usage: ledger threw', e instanceof Error ? e.message : String(e))
  }
}
