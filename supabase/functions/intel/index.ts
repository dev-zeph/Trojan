import { supabase } from '../_shared/supabase.ts'
import { validateToken, corsHeaders } from '../_shared/auth.ts'
import { parseBody } from '../_shared/body.ts'
import { chunk, groupByEcosystem, parseRequest, rowMatchesWanted } from './lib.ts'

// Trojan intel: advisories for the packages in a project's lockfile.
//
// CONTRACT (the Go client is written against exactly this)
//   POST, Authorization: Bearer <supabase user access token>
//   Body: either raw JSON, or the base64 envelope used by the other functions
//         (see _shared/body.ts): { "encoded": "<base64(utf8 JSON)>" }.
//         Prefer the envelope (Cloudflare WAF). The JSON itself is:
//         { "packages": [{ "ecosystem": "npm", "name": "next", "version": "14.1.0" }],
//           "since"?: ISO8601 }       // max 5000 packages
//   401 { "error": "unauthorized" }   (any signed-in account may use intel)
//   (402 subscription_required is reserved; the Go client still handles it)
//   400 { "error": "<reason>" }
//   200 { "advisories": [...], "generated_at": ISO }
//
// Returns ALL non-withdrawn advisories for the requested (ecosystem, package)
// pairs. No version matching here: the client decides hits by exact installed
// version. `version` is only used for log counts. No tokens are spent.
// Ingest must store package names normalized (see migration 023).

const COLUMNS = 'id,source,kind,ecosystem,package,affected_ranges,affected_versions,' +
  'fixed_version,severity,summary,details,aliases,refs,published_at,updated_at,playbook_id'
const CHUNK = 200

Deno.serve(async (req) => {
  if (req.method === 'OPTIONS') return new Response(null, { headers: corsHeaders() })
  if (req.method !== 'POST') return json({ error: 'Method not allowed' }, 405)

  const token = req.headers.get('authorization')?.replace('Bearer ', '') ?? ''
  const user = await validateToken(token)
  // Intel is open to every signed-in account (free included). No plan check.
  if (!user) return json({ error: 'unauthorized' }, 401)

  let raw: unknown
  try {
    raw = await parseBody<unknown>(req)
  } catch {
    return json({ error: 'Malformed request body' }, 400)
  }
  const parsed = parseRequest(raw)
  if (!parsed.ok) return json({ error: parsed.error }, 400)
  const { packages, since } = parsed.value

  const grouped = groupByEcosystem(packages)
  const wanted = new Map<string, string[]>(grouped)
  const advisories: Record<string, unknown>[] = []
  const seen = new Set<string>()

  for (const [ecosystem, names] of grouped) {
    for (const part of chunk(names, CHUNK)) {
      let q = supabase
        .from('intel_advisories')
        .select(COLUMNS)
        .eq('ecosystem', ecosystem)
        .in('package', part)
        .is('withdrawn_at', null)
      if (since) q = q.gt('updated_at', since)
      const { data, error } = await q
      if (error) {
        console.error('intel: query failed', { userId: user.id, ecosystem, error: error.message })
        return json({ error: 'Could not load intel. Please try again.' }, 500)
      }
      type Row = Record<string, unknown> & { id: string; ecosystem: string; package: string }
      for (const row of (data ?? []) as unknown as Row[]) {
        if (seen.has(row.id) || !rowMatchesWanted(row, wanted)) continue
        seen.add(row.id)
        advisories.push(row)
      }
    }
  }

  console.log('intel: served', {
    userId: user.id, packages: packages.length,
    withVersion: packages.filter((p) => p.version).length, advisories: advisories.length,
  })

  return json({ advisories, generated_at: new Date().toISOString() })
})

function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...corsHeaders(), 'Content-Type': 'application/json' },
  })
}
