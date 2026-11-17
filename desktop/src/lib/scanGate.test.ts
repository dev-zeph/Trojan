import { describe, expect, it, vi } from "vitest";
import {
  MIN_SCAN_TOKENS, SIGN_IN_TO_SCAN, evaluateScanGate, fetchLicenseBalance, runScanGate,
} from "./scanGate";

describe("evaluateScanGate", () => {
  it("blocks when signed out, with the sign-in prompt", () => {
    const g = evaluateScanGate(false, 9999);
    expect(g).toEqual({ ok: false, reason: "signed_out", message: SIGN_IN_TO_SCAN });
    expect(SIGN_IN_TO_SCAN).toBe("Sign in to scan. Every account gets 500 free tokens a month.");
  });

  it("blocks below the minimum and shows the balance", () => {
    const g = evaluateScanGate(true, MIN_SCAN_TOKENS - 1);
    expect(g.ok).toBe(false);
    if (!g.ok && g.reason === "low_tokens") {
      expect(g.balance).toBe(49);
      expect(g.message).toContain("You have 49");
      expect(g.message).toContain("at least 50");
    } else throw new Error("expected low_tokens");
  });

  it("passes at the minimum and above", () => {
    expect(evaluateScanGate(true, MIN_SCAN_TOKENS)).toEqual({ ok: true });
    expect(evaluateScanGate(true, 500)).toEqual({ ok: true });
  });

  it("lets the scan start when the balance cannot be read (server still enforces)", () => {
    expect(evaluateScanGate(true, null)).toEqual({ ok: true });
  });
});

describe("runScanGate", () => {
  it("does not touch the network when signed out", async () => {
    const fetchBalance = vi.fn();
    const g = await runScanGate({ signedIn: false, fetchBalance });
    expect(g.ok).toBe(false);
    expect(fetchBalance).not.toHaveBeenCalled();
  });

  it("reads the (granting) license balance before deciding", async () => {
    const order: string[] = [];
    const fetchBalance = vi.fn(async () => { order.push("grant+read"); return 500; });
    const g = await runScanGate({ signedIn: true, fetchBalance });
    order.push("decide");
    expect(g.ok).toBe(true);
    expect(order).toEqual(["grant+read", "decide"]);
  });

  it("blocks a drained account", async () => {
    const g = await runScanGate({ signedIn: true, fetchBalance: async () => 10 });
    expect(g.ok).toBe(false);
  });
});

describe("fetchLicenseBalance", () => {
  it("calls the license endpoint (which grants the month's tokens) with the token", async () => {
    const f = vi.fn().mockResolvedValue({ ok: true, json: async () => ({ tokenBalance: 500 }) });
    const b = await fetchLicenseBalance("https://x.supabase.co", "tok", f as unknown as typeof fetch);
    expect(b).toBe(500);
    expect(f).toHaveBeenCalledWith("https://x.supabase.co/functions/v1/license", {
      headers: { Authorization: "Bearer tok" },
    });
  });

  it("returns null on failure", async () => {
    const f = vi.fn().mockRejectedValue(new Error("offline"));
    expect(await fetchLicenseBalance("u", "t", f as unknown as typeof fetch)).toBeNull();
    const g = vi.fn().mockResolvedValue({ ok: false });
    expect(await fetchLicenseBalance("u", "t", g as unknown as typeof fetch)).toBeNull();
  });
});
