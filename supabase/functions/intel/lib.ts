// Pure logic for the intel edge function (no Deno/Supabase imports, so it is
// unit-testable in isolation).

export const MAX_PACKAGES = 5000
export const ECOSYSTEMS = [
  'npm', 'pypi', 'go', 'maven', 'rubygems', 'packagist', 'cargo', 'nuget',
] as const
export type Ecosystem = typeof ECOSYSTEMS[number]

export interface PackageQuery { ecosystem: Ecosystem; name: string; version?: string }
export interface IntelRequest { packages: PackageQuery[]; since: string | null }

export type ParseResult =
  | { ok: true; value: IntelRequest }
  | { ok: false; error: string }

/** PEP 503: lowercase, runs of - _ . collapse to a single "-". */
export function normalizePypi(name: string): string {
  return name.toLowerCase().replace(/[-_.]+/g, '-')
}

/** Normalize a package name for comparison, per ecosystem. */
export function normalizeName(ecosystem: string, name: string): string {
  const n = name.trim()
  return ecosystem === 'pypi' ? normalizePypi(n) : n
}

export function parseRequest(raw: unknown): ParseResult {
  if (!raw || typeof raw !== 'object') return { ok: false, error: 'Request body must be a JSON object.' }
  const body = raw as Record<string, unknown>
  if (!Array.isArray(body.packages)) return { ok: false, error: '"packages" must be an array.' }
  if (body.packages.length > MAX_PACKAGES) {
    return { ok: false, error: `At most ${MAX_PACKAGES} packages per request.` }
  }

  const packages: PackageQuery[] = []
  for (let i = 0; i < body.packages.length; i++) {
    const p = body.packages[i] as Record<string, unknown> | null
    if (!p || typeof p !== 'object') return { ok: false, error: `packages[${i}] must be an object.` }
    if (typeof p.ecosystem !== 'string') return { ok: false, error: `packages[${i}].ecosystem must be a string.` }
    const ecosystem = p.ecosystem.trim().toLowerCase()
    if (!(ECOSYSTEMS as readonly string[]).includes(ecosystem)) {
      return { ok: false, error: `packages[${i}].ecosystem "${p.ecosystem}" is not supported.` }
    }
    if (typeof p.name !== 'string' || !p.name.trim() || p.name.length > 300) {
      return { ok: false, error: `packages[${i}].name must be a non-empty string.` }
    }
    if (p.version !== undefined && typeof p.version !== 'string') {
      return { ok: false, error: `packages[${i}].version must be a string.` }
    }
    packages.push({
      ecosystem: ecosystem as Ecosystem,
      name: normalizeName(ecosystem, p.name),
      version: p.version as string | undefined,
    })
  }

  let since: string | null = null
  if (body.since !== undefined && body.since !== null) {
    if (typeof body.since !== 'string' || Number.isNaN(Date.parse(body.since))) {
      return { ok: false, error: '"since" must be an ISO 8601 timestamp.' }
    }
    since = new Date(body.since).toISOString()
  }
  return { ok: true, value: { packages, since } }
}

/** Group package names by ecosystem, de-duplicated. */
export function groupByEcosystem(packages: PackageQuery[]): Map<Ecosystem, string[]> {
  const sets = new Map<Ecosystem, Set<string>>()
  for (const p of packages) {
    if (!sets.has(p.ecosystem)) sets.set(p.ecosystem, new Set())
    sets.get(p.ecosystem)!.add(p.name)
  }
  const out = new Map<Ecosystem, string[]>()
  for (const [k, v] of sets) out.set(k, [...v])
  return out
}

export function chunk<T>(items: T[], size: number): T[][] {
  const out: T[][] = []
  for (let i = 0; i < items.length; i += size) out.push(items.slice(i, i + size))
  return out
}

/**
 * Safety net on returned rows: the stored name is normalized the same way as
 * the request before comparing (ingest should already store normalized names,
 * see migration 023).
 */
export function rowMatchesWanted(
  row: { ecosystem: string; package: string },
  wanted: Map<string, string[]>,
): boolean {
  const names = wanted.get(row.ecosystem)
  if (!names) return false
  return names.includes(normalizeName(row.ecosystem, row.package))
}
