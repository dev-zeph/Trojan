// Org-context persistence + the /api/context wire.
//
// Two storage layers, on purpose:
//
//   1. The project's .trojan/context.yaml, written by the embedded Go server
//      via /api/context. This is the source of truth for a scanned project,
//      and it never leaves the machine.
//   2. A local "draft" in the desktop store (trojan-store.json). Onboarding
//      runs before any project has been opened, so there is no server yet.
//      The draft holds what the user authored during onboarding until a scan
//      server exists, at which point syncDraftToServer writes it into the
//      project (but never over a context that project already has).
//
// The GET/POST contract, matched exactly:
//   GET  ${serverUrl}/api/context -> { exists: boolean, context: OrgContext | null }
//   POST ${serverUrl}/api/context  (OrgContext body) -> { ok: true, path: string }

import { getStore } from "./store";
import type { OrgContext, InferResult, ContextChanges } from "../types";

export const CONTEXT_DRAFT_KEY     = "org-context-draft";
export const CONTEXT_ONBOARDED_KEY = "org-context-onboarded";

export function emptyOrgContext(): OrgContext {
  return { app: { name: "", description: "" }, sensitive_data: [], trust_boundaries: [], threat_actors: [] };
}

// True once the user has authored anything worth persisting. Used to decide
// whether onboarding produced a draft, and whether to auto-sync it.
export function orgContextHasContent(c: OrgContext | null | undefined): boolean {
  if (!c) return false;
  return Boolean(
    c.app?.name?.trim() ||
    c.app?.description?.trim() ||
    (c.sensitive_data && c.sensitive_data.length > 0) ||
    (c.trust_boundaries && c.trust_boundaries.length > 0) ||
    (c.threat_actors && c.threat_actors.length > 0),
  );
}

function cleanList(items?: string[]): string[] | undefined {
  if (!items) return undefined;
  const out = items.map((s) => s.trim()).filter(Boolean);
  return out.length > 0 ? out : undefined;
}

// Trims whitespace and drops empty rows/fields so we never POST placeholder
// noise into the YAML file. Optional fields are omitted when empty so the
// snake_case JSON round-trips cleanly through the Go struct's omitempty tags.
export function normalizeOrgContext(c: OrgContext): OrgContext {
  return {
    app: {
      name: c.app?.name?.trim() ?? "",
      description: c.app?.description?.trim() ?? "",
    },
    sensitive_data: (c.sensitive_data ?? [])
      .filter((s) => s.category?.trim())
      .map((s) => ({
        category: s.category.trim(),
        description: s.description?.trim() || undefined,
        file_patterns: cleanList(s.file_patterns),
        symbol_patterns: cleanList(s.symbol_patterns),
      })),
    trust_boundaries: (c.trust_boundaries ?? [])
      .filter((b) => b.name?.trim())
      .map((b) => ({
        name: b.name.trim(),
        description: b.description?.trim() || undefined,
        file_patterns: cleanList(b.file_patterns),
        symbol_patterns: cleanList(b.symbol_patterns),
      })),
    threat_actors: (c.threat_actors ?? [])
      .filter((a) => a.name?.trim())
      .map((a) => ({
        name: a.name.trim(),
        description: a.description?.trim() || undefined,
        targets: cleanList(a.targets),
      })),
    data_stores: cleanList(c.data_stores),
    auth_model: normalizeAuth(c),
    third_party_services: cleanList(c.third_party_services),
    learned: c.learned && c.learned.length > 0 ? c.learned : undefined,
  };
}

function normalizeAuth(c: OrgContext): OrgContext["auth_model"] {
  const a = c.auth_model;
  if (!a) return undefined;
  const who = a.who_logs_in?.trim() || undefined;
  const roles = cleanList(a.roles);
  if (!who && !roles && !a.admin_area) return undefined;
  return { who_logs_in: who, roles, admin_area: a.admin_area || undefined };
}

// ── Local draft (pre-server / offline) ─────────────────────────────────────
export async function loadContextDraft(): Promise<OrgContext | null> {
  try { const s = await getStore(); return (await s.get<OrgContext>(CONTEXT_DRAFT_KEY)) ?? null; }
  catch { return null; }
}

export async function saveContextDraft(c: OrgContext): Promise<void> {
  try { const s = await getStore(); await s.set(CONTEXT_DRAFT_KEY, normalizeOrgContext(c)); } catch { /* store unavailable */ }
}

export async function clearContextDraft(): Promise<void> {
  try { const s = await getStore(); await s.delete(CONTEXT_DRAFT_KEY); } catch { /* store unavailable */ }
}

export async function isContextOnboarded(): Promise<boolean> {
  try { const s = await getStore(); return (await s.get<boolean>(CONTEXT_ONBOARDED_KEY)) ?? false; }
  catch { return false; }
}

export async function setContextOnboarded(v: boolean): Promise<void> {
  try { const s = await getStore(); await s.set(CONTEXT_ONBOARDED_KEY, v); } catch { /* store unavailable */ }
}

// ── /api/context wire ──────────────────────────────────────────────────────
function projectQuery(projectPath?: string): string {
  return projectPath ? `?project_path=${encodeURIComponent(projectPath)}` : "";
}

export async function fetchOrgContext(serverUrl: string, projectPath?: string): Promise<{ exists: boolean; context: OrgContext | null }> {
  const res = await fetch(`${serverUrl}/api/context${projectQuery(projectPath)}`);
  if (!res.ok) throw new Error(`Could not load project context (${res.status})`);
  const data = await res.json();
  return { exists: Boolean(data?.exists), context: (data?.context ?? null) as OrgContext | null };
}

export async function postOrgContext(serverUrl: string, ctx: OrgContext, projectPath?: string): Promise<{ ok: boolean; path: string }> {
  const res = await fetch(`${serverUrl}/api/context${projectQuery(projectPath)}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(normalizeOrgContext(ctx)),
  });
  if (!res.ok) throw new Error(`Could not save project context (${res.status})`);
  const data = await res.json();
  return { ok: Boolean(data?.ok), path: String(data?.path ?? "") };
}

// Called once a scan server is available. If the user authored a context during
// onboarding and this project does not already have one, write the draft into
// the project's .trojan/context.yaml. Never clobbers a context the project
// already carries. Silently gives up if the server or endpoint is not ready,
// so a failure here never breaks a scan; the next scan retries.
export async function syncDraftToServer(serverUrl: string): Promise<void> {
  try {
    const draft = await loadContextDraft();
    if (!orgContextHasContent(draft)) return;
    const { exists } = await fetchOrgContext(serverUrl);
    if (exists) return;
    await postOrgContext(serverUrl, draft!);
  } catch {
    // server not ready, endpoint not yet deployed, or offline -- retry next scan
  }
}

// ── Understanding your app (infer + changes) ───────────────────────────────
export type InferErrorKind = "out_of_tokens" | "not_signed_in" | "failed";

export class InferError extends Error {
  kind: InferErrorKind;
  constructor(kind: InferErrorKind, message: string) {
    super(message);
    this.kind = kind;
  }
}

// POST /api/context/infer. Throws InferError; kind "out_of_tokens" means the
// UI should offer the token top-up instead of a generic failure.
export async function inferOrgContext(serverUrl: string, projectPath: string, description: string): Promise<InferResult> {
  let res: Response;
  try {
    res = await fetch(`${serverUrl}/api/context/infer`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ project_path: projectPath, description }),
    });
  } catch {
    throw new InferError("failed", "Trojan couldn't reach itself just now. Please try again.");
  }
  if (res.status === 402) {
    const data = await res.json().catch(() => ({}));
    throw new InferError("out_of_tokens", data?.message || "You're out of tokens.");
  }
  if (res.status === 401) {
    throw new InferError("not_signed_in", "Please sign in to Trojan first.");
  }
  if (!res.ok) {
    const data = await res.json().catch(() => ({}));
    throw new InferError("failed", data?.message || "Trojan couldn't work out what your app does just now. Please try again.");
  }
  const data = await res.json();
  return {
    draft: data.draft as OrgContext,
    questions: Array.isArray(data.questions) ? data.questions : [],
    mismatches: Array.isArray(data.mismatches) ? data.mismatches : [],
    free: Boolean(data.free),
  };
}

// GET /api/context/changes. Returns null when there is nothing to report or
// the check could not run (this is a nicety, so it never throws).
export async function fetchContextChanges(serverUrl: string, projectPath: string): Promise<ContextChanges | null> {
  try {
    const res = await fetch(`${serverUrl}/api/context/changes${projectQuery(projectPath)}`);
    if (!res.ok) return null;
    const data = await res.json();
    if (!data?.changed) return null;
    return data.changes as ContextChanges;
  } catch {
    return null;
  }
}
