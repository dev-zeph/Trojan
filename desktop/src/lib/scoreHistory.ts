import { getStore } from "./store";
import { SCORES_KEY } from "../constants";
import type { ThreatLabResult } from "../types";

// ── Security Score history ────────────────────────────────────────────────
// The Security Score (100 - threat_index, plus an A-F grade) only exists once a
// Security Report has been generated. Before this module the result lived in
// one global React state: it was lost on restart, shared across projects, and
// never compared with an earlier run. Here it is kept per project, on disk,
// so "Was 58, now 74" works across restarts.

export const MAX_HISTORY = 20;

export interface ScoreEntry {
  score: number;      // 0-100, higher = more secure
  grade: string;
  at: string;         // ISO time the report was generated
  scanAt: string;     // ISO time of the scan this score was based on
}

export interface ProjectScores {
  entries: ScoreEntry[];                 // oldest first
  report: ThreatLabResult | null;        // the latest full report, for download after a restart
}

export type ScoreStore = Record<string, ProjectScores>;

// One key per project, whatever trailing slash the path arrived with.
export function projectKey(path: string): string {
  const p = (path ?? "").trim();
  return p.length > 1 ? p.replace(/[\\/]+$/, "") : p;
}

export function scoreFromResult(r: Pick<ThreatLabResult, "threat_index">): number {
  return Math.max(0, Math.min(100, Math.round(100 - r.threat_index)));
}

export function recordScore(
  store: ScoreStore,
  path: string,
  result: ThreatLabResult,
  scanAt: string,
  now: Date = new Date(),
): ScoreStore {
  const key = projectKey(path);
  const prev = store[key]?.entries ?? [];
  const entry: ScoreEntry = { score: scoreFromResult(result), grade: result.grade, at: now.toISOString(), scanAt };
  return { ...store, [key]: { entries: [...prev, entry].slice(-MAX_HISTORY), report: result } };
}

export function latestEntry(store: ScoreStore, path: string): ScoreEntry | null {
  const e = store[projectKey(path)]?.entries ?? [];
  return e.length ? e[e.length - 1] : null;
}

export function previousEntry(store: ScoreStore, path: string): ScoreEntry | null {
  const e = store[projectKey(path)]?.entries ?? [];
  return e.length > 1 ? e[e.length - 2] : null;
}

export function latestReport(store: ScoreStore, path: string): ThreatLabResult | null {
  return store[projectKey(path)]?.report ?? null;
}

export type ScoreChange =
  | { kind: "first" }
  | { kind: "up" | "down" | "same"; was: number; now: number; diff: number };

export function scoreChange(latest: ScoreEntry | null, previous: ScoreEntry | null): ScoreChange | null {
  if (!latest) return null;
  if (!previous) return { kind: "first" };
  const diff = latest.score - previous.score;
  return { kind: diff > 0 ? "up" : diff < 0 ? "down" : "same", was: previous.score, now: latest.score, diff };
}

// Plain words, no em dashes.
export function changeText(c: ScoreChange | null): string {
  if (!c || c.kind === "first") return "";
  if (c.kind === "same") return `Still ${c.now}. Same as last time.`;
  return `Was ${c.was}, now ${c.now}`;
}

// A score is out of date once the project was scanned again after the scan the
// score was built from. A scan's recorded start time is always earlier than the
// finish time stored with its report, so this cannot misfire on the same scan.
export function isScoreStale(entry: ScoreEntry | null, lastScannedAt: string | undefined): boolean {
  if (!entry || !lastScannedAt) return false;
  const scan = Date.parse(entry.scanAt);
  const last = Date.parse(lastScannedAt);
  if (Number.isNaN(scan) || Number.isNaN(last)) return false;
  return last > scan;
}

// Findings the AI false-positive check hid must not drag the score down.
// Go serializes the field as "Verdict"; tolerate lowercase and a missing field.
export function excludeHiddenFalseAlarms<T>(findings: T[]): T[] {
  return (findings ?? []).filter((f) => {
    const o = (f ?? {}) as Record<string, unknown>;
    const v = o.Verdict ?? o.verdict;
    return typeof v !== "string" || v.toLowerCase() !== "likely_fp";
  });
}

// ── Disk ──────────────────────────────────────────────────────────────────

export async function loadScoreStore(): Promise<ScoreStore> {
  try {
    const s = await getStore();
    return (await s.get<ScoreStore>(SCORES_KEY)) ?? {};
  } catch { return {}; }
}

export async function saveScoreStore(store: ScoreStore): Promise<void> {
  try {
    const s = await getStore();
    await s.set(SCORES_KEY, store);
    await s.save();
  } catch {}
}
