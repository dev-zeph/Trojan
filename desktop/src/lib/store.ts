import { load } from "@tauri-apps/plugin-store";
import { STORE_KEY, PROFILE_KEY } from "../constants";
import type { RecentProject, ScanType, UserProfile } from "../types";

export async function getStore() { return load("trojan-store.json", { autoSave: true }); }

export async function loadProfile(): Promise<UserProfile | null> {
  try { const s = await getStore(); return (await s.get<UserProfile>(PROFILE_KEY)) ?? null; }
  catch { return null; }
}

export async function saveProfile(p: UserProfile) {
  try { const s = await getStore(); await s.set(PROFILE_KEY, p); } catch {}
}

export async function loadRecent(): Promise<RecentProject[]> {
  try {
    const s = await getStore();
    const raw = (await s.get<RecentProject[]>(STORE_KEY)) ?? [];
    return raw.filter((r) => r && r.path && r.type);
  } catch { return []; }
}

export async function saveRecent(path: string, type: ScanType) {
  try {
    const s = await getStore();
    const existing = (await s.get<RecentProject[]>(STORE_KEY)) ?? [];
    const name = path.split("/").pop() ?? path;
    const prev = existing.find((r) => r.path === path);
    const entry: RecentProject = { path, name, type, scannedAt: new Date().toISOString(), reportUrl: prev?.reportUrl };
    await s.set(STORE_KEY, [entry, ...existing.filter((r) => r.path !== path)].slice(0, 10));
  } catch {}
}

export async function updateRecentUrl(path: string, reportUrl: string) {
  try {
    const s = await getStore();
    const existing = (await s.get<RecentProject[]>(STORE_KEY)) ?? [];
    await s.set(STORE_KEY, existing.map((r) => r.path === path ? { ...r, reportUrl } : r));
  } catch {}
}

export async function updateRecentCachePath(path: string, cachePath: string) {
  try {
    const s = await getStore();
    const existing = (await s.get<RecentProject[]>(STORE_KEY)) ?? [];
    await s.set(STORE_KEY, existing.map((r) => r.path === path ? { ...r, cachePath } : r));
  } catch {}
}

export async function deleteRecentEntry(path: string): Promise<RecentProject[]> {
  try {
    const s = await getStore();
    const existing = (await s.get<RecentProject[]>(STORE_KEY)) ?? [];
    const updated = existing.filter((r) => r.path !== path);
    await s.set(STORE_KEY, updated);
    await s.save();
    return updated;
  } catch { return []; }
}
