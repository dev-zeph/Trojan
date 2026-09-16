// Small shared helpers. Nothing backend-specific lives here.

import type { TrojanFrame } from './types.ts'

/**
 * Run `fn` over `items` with at most `limit` in flight.
 * Used to bound the per-issue lookups the read API does for DAST attribution —
 * serial is too slow on a 50-issue page, unbounded hammers the backend.
 */
export async function mapLimit<T, R>(
  items: readonly T[],
  limit: number,
  fn: (item: T, index: number) => Promise<R>,
): Promise<R[]> {
  const results = new Array<R>(items.length)
  let cursor = 0

  const worker = async (): Promise<void> => {
    for (;;) {
      const i = cursor++
      if (i >= items.length) return
      results[i] = await fn(items[i] as T, i)
    }
  }

  const workers = Array.from({ length: Math.max(1, Math.min(limit, items.length)) }, worker)
  await Promise.all(workers)
  return results
}

/**
 * Human culprit line, e.g. "routes/checkout.js:42 in applyDiscount".
 * Sentry frame order puts the innermost/crashing frame LAST, so the most
 * specific in-app frame is found by scanning backwards.
 */
export function culpritFromFrames(frames: readonly TrojanFrame[]): string {
  if (frames.length === 0) return ''

  let chosen: TrojanFrame | undefined
  for (let i = frames.length - 1; i >= 0; i--) {
    const frame = frames[i]
    if (frame?.inApp) {
      chosen = frame
      break
    }
  }
  chosen ??= frames[frames.length - 1]
  if (!chosen) return ''

  const where = chosen.lineno !== null ? `${chosen.filename}:${chosen.lineno}` : chosen.filename
  if (!where) return chosen.function ? `in ${chosen.function}` : ''
  return chosen.function ? `${where} in ${chosen.function}` : where
}

/** fetch with a hard timeout so an unresponsive backend cannot hang the shim. */
export async function fetchWithTimeout(
  url: string,
  init: RequestInit,
  timeoutMs: number,
): Promise<Response> {
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), timeoutMs)
  try {
    return await fetch(url, { ...init, signal: controller.signal })
  } finally {
    clearTimeout(timer)
  }
}
