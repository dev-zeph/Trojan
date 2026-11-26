/**
 * Pseudonymous log reference for a user id: the first 12 hex chars of
 * sha256("synthesize-log:" + id). Same derivation as logRef in synthesize, so
 * log lines for one user can be correlated across functions without the id
 * itself appearing in logs. Pseudonymous, not anonymous.
 */
export async function logRef(id: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(`synthesize-log:${id}`))
  return Array.from(new Uint8Array(digest).slice(0, 6), (b) => b.toString(16).padStart(2, '0')).join('')
}
