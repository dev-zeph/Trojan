// Website test template cache (dast_template_cache), per account.
//
// Rows are keyed by userCrawlKey: sha256 over the account id plus the scrubbed
// crawl (crawl_scrub.ts), and every read and write is also filtered by
// created_by. A template is only ever served back to the account that paid for
// it. Rows live 24 hours: expired rows are deleted on each request
// (purgeExpiredTemplates), since pg_cron isn't enabled on the project.

import { canonicalCrawl, type DastContext } from './crawl_scrub.ts'

export const TEMPLATE_CACHE_TTL_MS = 24 * 60 * 60 * 1000
const TABLE = 'dast_template_cache'

export interface TemplateResult {
  templates: string[]
  rationale: string
}

type DbError = { message: string; code?: string } | null

// The slice of the supabase-js client these functions use, so tests can fake it.
export interface CacheClient {
  from(table: string): {
    select(cols: string): {
      eq(c: string, v: string): { eq(c: string, v: string): { maybeSingle(): PromiseLike<{ data: Record<string, unknown> | null; error: DbError }> } }
    }
    delete(): {
      lt(c: string, v: string): PromiseLike<{ error: DbError; count?: number | null }>
    }
    upsert(row: Record<string, unknown>, opts: { onConflict: string }): PromiseLike<{ error: DbError }>
  }
}

function hex(buf: ArrayBuffer): string {
  return Array.from(new Uint8Array(buf), b => b.toString(16).padStart(2, '0')).join('')
}

/** Per-account cache key: sha256 of the account id and the scrubbed crawl. */
export async function userCrawlKey(userId: string, ctx: DastContext): Promise<string> {
  if (!userId) throw new Error('userCrawlKey: userId is required')
  const text = `user ${userId}\n${canonicalCrawl(ctx)}`
  return hex(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text)))
}

/** Cutoff timestamp: rows created before it are expired. */
export function expiryCutoff(now: number = Date.now()): string {
  return new Date(now - TEMPLATE_CACHE_TTL_MS).toISOString()
}

/** True when a row's created_at is missing, unreadable or older than 24 hours. */
export function isExpired(createdAt: unknown, now: number = Date.now()): boolean {
  if (typeof createdAt !== 'string') return true
  const t = new Date(createdAt).getTime()
  return !Number.isFinite(t) || now - t > TEMPLATE_CACHE_TTL_MS
}

/** Delete every row older than 24 hours. Never throws; returns false on error. */
export async function purgeExpiredTemplates(db: CacheClient, now: number = Date.now()): Promise<boolean> {
  try {
    const { error } = await db.from(TABLE).delete().lt('created_at', expiryCutoff(now))
    if (error) {
      console.error('dast-templates: expiry delete failed:', error.message, error.code ?? '')
      return false
    }
    return true
  } catch (e) {
    console.error('dast-templates: expiry delete failed:', e instanceof Error ? e.message : String(e))
    return false
  }
}

/** This account's live row for the key, or null. */
export async function getCachedTemplates(db: CacheClient, userId: string, key: string, now: number = Date.now()): Promise<TemplateResult | null> {
  const { data, error } = await db.from(TABLE)
    .select('templates, rationale, created_at')
    .eq('created_by', userId)
    .eq('crawl_hash', key)
    .maybeSingle()
  if (error) {
    console.error('dast-templates: cache read error:', error.message, error.code ?? '')
    return null
  }
  if (!data || isExpired(data.created_at, now)) return null
  if (!Array.isArray(data.templates) || !data.templates.every(t => typeof t === 'string')) return null
  return { templates: data.templates as string[], rationale: typeof data.rationale === 'string' ? data.rationale : '' }
}

/** Store (or refresh) this account's row for the key. Never throws. */
export async function saveCachedTemplates(db: CacheClient, userId: string, key: string, result: TemplateResult): Promise<boolean> {
  try {
    const { error } = await db.from(TABLE).upsert({
      created_by: userId,
      crawl_hash: key,
      templates: result.templates,
      rationale: result.rationale,
      created_at: new Date().toISOString(),
    }, { onConflict: 'created_by,crawl_hash' })
    if (error) {
      console.error('dast-templates: cache write error:', error.message, error.code ?? '')
      return false
    }
    return true
  } catch (e) {
    console.error('dast-templates: cache write error:', e instanceof Error ? e.message : String(e))
    return false
  }
}
