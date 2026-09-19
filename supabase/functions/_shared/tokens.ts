import { supabase } from './supabase.ts'
import { FREE_MONTHLY_TOKENS } from './pricing.ts'

// Trojan Tokens: the BILLING unit customers buy and spend. Not LLM tokens.
//
// This file holds only the DATABASE-backed balance operations. The pure
// cost->token arithmetic lives in pricing.ts so it can be unit-tested without
// a Supabase client; it is re-exported here so callers have one import.

export {
  TOKENS_PER_USD_COST, tokensForCostMicros, tokensForAction,
  PRICING_MODE, FLAT_PRICES, FREE_MONTHLY_TOKENS,
} from './pricing.ts'

// ── Balance operations ────────────────────────────────────────────────────

export class InsufficientTokens extends Error {
  constructor(public readonly balance: number, public readonly needed: number) {
    super('insufficient_tokens')
    this.name = 'InsufficientTokens'
  }
}

export async function getBalance(userId: string): Promise<number> {
  const { data, error } = await supabase
    .from('token_balances')
    .select('balance')
    .eq('user_id', userId)
    .maybeSingle()

  if (error) {
    console.error('tokens: balance read failed', { userId, error: error.message })
    return 0
  }
  return (data?.balance as number | undefined) ?? 0
}

export interface SpendArgs {
  userId: string
  tokens: number
  feature: string
  runId?: string | null
  model?: string | null
  costMicros?: number | null
  /** Deterministic key so a client retry after a timeout cannot double-charge. */
  idempotencyKey?: string | null
}

/**
 * Debit tokens. Returns the new balance.
 *
 * Throws InsufficientTokens when the customer cannot cover it -- callers should
 * map that to a 402 so the UI can prompt a top-up. All other failures also
 * throw: unlike usage metering (which must never break a scan), a failed DEBIT
 * must not be swallowed, or work gets given away for free.
 */
export async function spendTokens(args: SpendArgs): Promise<number> {
  const { data, error } = await supabase.rpc('spend_tokens', {
    p_user_id:         args.userId,
    p_amount:          args.tokens,
    p_feature:         args.feature,
    p_run_id:          args.runId ?? null,
    p_model:           args.model ?? null,
    p_cost_micros:     args.costMicros ?? null,
    p_idempotency_key: args.idempotencyKey ?? null,
  })

  if (error) {
    if (error.message?.includes('insufficient_tokens')) {
      const balance = await getBalance(args.userId)
      throw new InsufficientTokens(balance, args.tokens)
    }
    console.error('tokens: spend failed', { ...args, error: error.message })
    throw new Error(`token spend failed: ${error.message}`)
  }
  return (data as number) ?? 0
}

export async function grantTokens(
  userId: string, tokens: number, reason: string, idempotencyKey?: string | null,
): Promise<number> {
  const { data, error } = await supabase.rpc('grant_tokens', {
    p_user_id:         userId,
    p_amount:          tokens,
    p_reason:          reason,
    p_idempotency_key: idempotencyKey ?? null,
  })

  if (error) {
    console.error('tokens: grant failed', { userId, tokens, reason, error: error.message })
    throw new Error(`token grant failed: ${error.message}`)
  }
  return (data as number) ?? 0
}

/**
 * Grant a subscription's monthly allowance. Call from stripe-webhook on
 * `invoice.paid`, using the invoice id as the idempotency key.
 *
 * Tops the subscription bucket UP TO the allowance, capped at 2x so one unused
 * month carries over and a second does not.
 */
export async function grantSubscriptionTokens(
  userId: string, allowance: number, reason = 'subscription_renewal', idempotencyKey?: string | null,
): Promise<number> {
  const { data, error } = await supabase.rpc('grant_subscription_tokens', {
    p_user_id:         userId,
    p_allowance:       allowance,
    p_reason:          reason,
    p_idempotency_key: idempotencyKey ?? null,
  })
  if (error) {
    console.error('tokens: subscription grant failed', { userId, allowance, error: error.message })
    throw new Error(`subscription grant failed: ${error.message}`)
  }
  return (data as number) ?? 0
}

/**
 * Top the user up with this month's free tokens if they have not had them yet.
 *
 * Deliberately NOT called from getBalance: this takes a row lock, and
 * synthesize runs once per finding, so putting it on every read path would mean
 * hundreds of lock acquisitions per scan. Call it from the low-frequency paths
 * instead -- license (polled by the desktop) and the agentic-dast pre-flight
 * gate -- which is enough for a user to always find their free tokens present.
 *
 * Never throws: a failure here must not block a paying customer's work.
 */
export async function ensureMonthlyFreeTokens(userId: string, amount = FREE_MONTHLY_TOKENS): Promise<number> {
  try {
    const { data, error } = await supabase.rpc('ensure_monthly_free_tokens', {
      p_user_id: userId,
      p_amount:  amount,
    })
    if (error) {
      console.error('tokens: free grant failed', { userId, error: error.message })
      return await getBalance(userId)
    }
    return (data as number) ?? 0
  } catch (e) {
    console.error('tokens: free grant threw', e instanceof Error ? e.message : String(e))
    return 0
  }
}
