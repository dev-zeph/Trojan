// Gate for starting a code scan: signed in AND enough tokens to start.
//
// This is the UX layer (a clear prompt instead of a doomed run). Enforcement of
// what the AI check costs is server-side in the triage and synthesize edge
// functions. Keep the minimum and the sign-in text in step with
// internal/scangate/scangate.go.

/** Balance needed to start a code scan. Why 50: see internal/scangate. */
export const MIN_SCAN_TOKENS = 50;

export const SIGN_IN_TO_SCAN = "Sign in to scan. Every account gets 500 free tokens a month.";

export function lowTokensMessage(balance: number): string {
  return `Not enough tokens to scan. You have ${balance.toLocaleString()} and a scan needs at least ${MIN_SCAN_TOKENS}. ` +
    "Top up, or wait for your free 500 tokens next month.";
}

export type ScanGate =
  | { ok: true }
  | { ok: false; reason: "signed_out"; message: string }
  | { ok: false; reason: "low_tokens"; message: string; balance: number };

/** Pure decision. `balance` null means it could not be read: let the scan start. */
export function evaluateScanGate(signedIn: boolean, balance: number | null): ScanGate {
  if (!signedIn) return { ok: false, reason: "signed_out", message: SIGN_IN_TO_SCAN };
  if (balance !== null && balance < MIN_SCAN_TOKENS) {
    return { ok: false, reason: "low_tokens", message: lowTokensMessage(balance), balance };
  }
  return { ok: true };
}

export interface GateDeps {
  signedIn: boolean;
  /**
   * Reads the balance from the license endpoint, which applies this month's
   * free grant first. Returns null when it cannot be read.
   */
  fetchBalance: () => Promise<number | null>;
}

/** Grant-then-check: the balance is always read fresh, after the monthly grant. */
export async function runScanGate(deps: GateDeps): Promise<ScanGate> {
  if (!deps.signedIn) return evaluateScanGate(false, null);
  const balance = await deps.fetchBalance();
  return evaluateScanGate(true, balance);
}

/** license endpoint call: grants the monthly tokens, then returns the balance. */
export async function fetchLicenseBalance(
  supabaseUrl: string,
  token: string,
  fetchImpl: typeof fetch = fetch,
): Promise<number | null> {
  try {
    const res = await fetchImpl(`${supabaseUrl}/functions/v1/license`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    if (!res.ok) return null;
    const data = await res.json();
    return typeof data.tokenBalance === "number" ? data.tokenBalance : null;
  } catch {
    return null;
  }
}
