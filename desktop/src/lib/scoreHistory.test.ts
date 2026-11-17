import { beforeEach, describe, expect, it, vi } from "vitest";
import type { ThreatLabResult } from "../types";

// In-memory stand-in for the Tauri store, shared across "restarts".
const disk = new Map<string, unknown>();
vi.mock("./store", () => ({
  getStore: async () => ({
    get: async (k: string) => disk.get(k),
    set: async (k: string, v: unknown) => { disk.set(k, JSON.parse(JSON.stringify(v))); },
    save: async () => {},
  }),
}));

import {
  MAX_HISTORY, changeText, excludeHiddenFalseAlarms, isScoreStale, latestEntry, latestReport,
  loadScoreStore, previousEntry, projectKey, recordScore, saveScoreStore, scoreChange,
} from "./scoreHistory";

function report(threat_index: number, grade: ThreatLabResult["grade"] = "C"): ThreatLabResult {
  return { threat_index, grade, verdict: "v", attack_vectors: [], priority_fixes: [], compliance_summary: "", key_risks: [] };
}

beforeEach(() => disk.clear());

describe("score history persistence", () => {
  it("survives a restart and keeps projects apart", async () => {
    let store = recordScore({}, "/p/shop", report(42), "2026-11-01T10:00:00Z", new Date("2026-11-01T10:05:00Z"));
    store = recordScore(store, "/p/other", report(10, "A"), "2026-11-01T10:00:00Z");
    await saveScoreStore(store);

    const reloaded = await loadScoreStore();
    expect(latestEntry(reloaded, "/p/shop")?.score).toBe(58);
    expect(latestEntry(reloaded, "/p/other")?.score).toBe(90);
    expect(latestReport(reloaded, "/p/shop")?.threat_index).toBe(42);
  });

  it("keeps earlier scores so before/after works after a restart", async () => {
    let store = recordScore({}, "/p/shop", report(42), "2026-11-01T10:00:00Z");
    store = recordScore(store, "/p/shop", report(26, "B"), "2026-11-02T10:00:00Z");
    await saveScoreStore(store);
    const reloaded = await loadScoreStore();
    expect(changeText(scoreChange(latestEntry(reloaded, "/p/shop"), previousEntry(reloaded, "/p/shop")))).toBe("Was 58, now 74");
  });

  it("treats a trailing slash as the same project and caps history", () => {
    let store = recordScore({}, "/p/shop/", report(40), "2026-11-01T10:00:00Z");
    for (let i = 0; i < MAX_HISTORY + 5; i++) store = recordScore(store, "/p/shop", report(40), "2026-11-01T10:00:00Z");
    expect(projectKey("/p/shop/")).toBe("/p/shop");
    expect(store["/p/shop"].entries).toHaveLength(MAX_HISTORY);
  });

  it("loads an empty store when nothing was saved", async () => {
    expect(await loadScoreStore()).toEqual({});
  });
});

describe("before and after", () => {
  it("says nothing for a first score, and 'Was X, now Y' for later ones", () => {
    const first = recordScore({}, "/p", report(42), "2026-11-01T10:00:00Z");
    expect(changeText(scoreChange(latestEntry(first, "/p"), previousEntry(first, "/p")))).toBe("");
    const second = recordScore(first, "/p", report(26), "2026-11-02T10:00:00Z");
    const c = scoreChange(latestEntry(second, "/p"), previousEntry(second, "/p"));
    expect(c).toMatchObject({ kind: "up", was: 58, now: 74, diff: 16 });
  });

  it("reports a drop and an unchanged score", () => {
    let s = recordScore({}, "/p", report(20), "2026-11-01T10:00:00Z");
    s = recordScore(s, "/p", report(30), "2026-11-02T10:00:00Z");
    expect(scoreChange(latestEntry(s, "/p"), previousEntry(s, "/p"))?.kind).toBe("down");
    s = recordScore(s, "/p", report(30), "2026-11-03T10:00:00Z");
    expect(changeText(scoreChange(latestEntry(s, "/p"), previousEntry(s, "/p")))).toBe("Still 70. Same as last time.");
  });
});

describe("stale after a rescan", () => {
  const entry = { score: 58, grade: "C", at: "2026-11-01T10:05:00Z", scanAt: "2026-11-01T10:04:00.5Z" };
  it("is fresh when no newer scan happened", () => {
    // A scan is recorded when it starts, before its finish time.
    expect(isScoreStale(entry, "2026-11-01T10:03:00Z")).toBe(false);
  });
  it("is stale once the project was scanned again", () => {
    expect(isScoreStale(entry, "2026-11-01T11:00:00Z")).toBe(true);
  });
  it("is never stale with no score or no scan time", () => {
    expect(isScoreStale(null, "2026-11-01T11:00:00Z")).toBe(false);
    expect(isScoreStale(entry, undefined)).toBe(false);
  });
});

describe("hidden false alarms", () => {
  it("drops likely_fp findings and keeps everything else", () => {
    const out = excludeHiddenFalseAlarms([
      { ID: "a", Verdict: "likely_fp" },
      { ID: "b", Verdict: "confirmed" },
      { ID: "c", Verdict: "needs_manual" },
      { ID: "d" },
      { ID: "e", verdict: "likely_fp" },
    ]);
    expect(out.map((f) => f.ID)).toEqual(["b", "c", "d"]);
  });
  it("tolerates a missing list", () => {
    expect(excludeHiddenFalseAlarms(undefined as unknown as unknown[])).toEqual([]);
  });
});
