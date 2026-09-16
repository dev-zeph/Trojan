// Loads crash-analytics/runtime.json plus the file-backed Trojan project
// registry. Deliberately imports nothing from ../supabase.ts or ../auth.ts —
// those throw at module load without env vars that do not exist here, and
// CONTRACT.md requires this service to boot with zero secrets.

import { randomBytes } from 'node:crypto'
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const HERE = dirname(fileURLToPath(import.meta.url))
// backend/src/errors -> repo root
export const REPO_ROOT = resolve(HERE, '..', '..', '..')
export const CRASH_ANALYTICS_DIR = join(REPO_ROOT, 'crash-analytics')
export const DATA_DIR = join(CRASH_ANALYTICS_DIR, '.data')

export const PORT = Number(process.env['ERRORS_PORT'] ?? 3002)
export const PUBLIC_HOST = process.env['ERRORS_PUBLIC_HOST'] ?? `localhost:${PORT}`

export interface RuntimeConfig {
  backend: string
  backendUrl: string
  backendProjectId: string
  backendPublicKey: string
  backendDsn: string
  backendApiToken: string
}

export interface TrojanProject {
  /**
   * The project id that appears in the Trojan DSN. MUST be numeric.
   *
   * The official Sentry SDKs parse the DSN path with the equivalent of
   * `int(path)` and raise BadDsn on anything else, so a friendly slug like
   * "trojan-demo" makes every real SDK refuse to initialise. Bugsink itself is
   * lenient here, which is exactly why this only shows up against a real client.
   */
  id: string
  /** human-readable identifier, shown in the UI and used in setup docs */
  slug: string
  name: string
  /** the public key that appears in the Trojan DSN handed to customers */
  publicKey: string
  /** which project inside the storage backend this maps onto */
  backendProjectId: string
  createdAt: string
}

const RUNTIME_PATH = join(CRASH_ANALYTICS_DIR, 'runtime.json')
const REGISTRY_PATH = join(DATA_DIR, 'projects.json')

function ensureDataDir(): void {
  if (!existsSync(DATA_DIR)) mkdirSync(DATA_DIR, { recursive: true })
}

let runtimeCache: RuntimeConfig | null = null

export function loadRuntime(): RuntimeConfig {
  if (runtimeCache) return runtimeCache
  if (!existsSync(RUNTIME_PATH)) {
    throw new Error(
      `crash-analytics/runtime.json not found at ${RUNTIME_PATH} — run crash-analytics/setup.sh first`,
    )
  }
  const raw = JSON.parse(readFileSync(RUNTIME_PATH, 'utf8')) as Partial<RuntimeConfig>
  const cfg: RuntimeConfig = {
    backend: raw.backend ?? 'bugsink',
    backendUrl: (raw.backendUrl ?? 'http://localhost:8000').replace(/\/+$/, ''),
    backendProjectId: String(raw.backendProjectId ?? '1'),
    backendPublicKey: raw.backendPublicKey ?? '',
    backendDsn: raw.backendDsn ?? '',
    backendApiToken: raw.backendApiToken ?? '',
  }
  runtimeCache = cfg
  return cfg
}

// ---------------------------------------------------------------------------
// Trojan project registry
// ---------------------------------------------------------------------------
//
// Customers authenticate against Trojan, never against the storage backend.
// The registry maps a Trojan project id + public key onto a backend project.

let registryCache: TrojanProject[] | null = null

export function loadRegistry(): TrojanProject[] {
  if (registryCache) return registryCache
  ensureDataDir()

  if (existsSync(REGISTRY_PATH)) {
    try {
      const parsed = JSON.parse(readFileSync(REGISTRY_PATH, 'utf8')) as unknown
      if (Array.isArray(parsed) && parsed.length > 0) {
        registryCache = parsed as TrojanProject[]
        return registryCache
      }
    } catch (err) {
      console.error('[errors] project registry unreadable, reseeding:', String(err))
    }
  }

  const runtime = loadRuntime()
  const seeded: TrojanProject[] = [
    {
      id: '1', // numeric: real Sentry SDKs reject a non-integer DSN project id
      slug: 'trojan-demo',
      name: 'Trojan Demo',
      publicKey: randomBytes(16).toString('hex'), // 32 hex chars
      backendProjectId: runtime.backendProjectId,
      createdAt: new Date().toISOString(),
    },
  ]
  writeFileSync(REGISTRY_PATH, JSON.stringify(seeded, null, 2))
  registryCache = seeded
  return seeded
}

export function defaultProject(): TrojanProject {
  const projects = loadRegistry()
  const first = projects[0]
  if (!first) throw new Error('project registry is empty')
  return first
}

export function findProjectById(id: string): TrojanProject | undefined {
  return loadRegistry().find(p => p.id === id)
}

/** Resolve + authenticate in one step. Returns undefined when the key is wrong. */
export function authenticateProject(id: string, publicKey: string | null): TrojanProject | undefined {
  const project = findProjectById(id)
  if (!project) return undefined
  if (!publicKey || publicKey !== project.publicKey) return undefined
  return project
}

export function trojanDsn(project: TrojanProject): string {
  return `http://${project.publicKey}@${PUBLIC_HOST}/${project.id}`
}

export function trojanIngestUrl(project: TrojanProject): string {
  return `http://${PUBLIC_HOST}/api/${project.id}/envelope/`
}
