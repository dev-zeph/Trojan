import type { UserProfile } from "../types";

// Presentation helpers extracted verbatim from App.tsx.

// Maps raw internal error strings (from Rust/Go/network) to user-friendly messages.
// Applied at every error surface so neither persona sees developer-facing text.
export function friendlyError(raw: string): string {
  const s = raw.toLowerCase();

  // ── Sidecar / spawn ──────────────────────────────────────────────────────
  if (s.includes("sidecar not found") || s.includes("sidecar"))
    return "Could not start the scanner. Try reinstalling Trojan.";
  if (s.includes("spawn failed") || s.includes("spawn"))
    return "The scanner couldn't launch. Restart the app and try again.";

  // ── Scan process exits ───────────────────────────────────────────────────
  if (s.includes("no scanners installed") || s.includes("trojan init"))
    return "Scanners aren't set up yet. Open a terminal and run: trojan init";
  if (s.includes("process exited") || s.includes("scan failed"))
    return "The scan stopped unexpectedly. Try running it again.";
  if (s.includes("server failed to start") || s.includes("could not start"))
    return "The scan report server failed to start. Restart the app and try again.";

  // ── Network ──────────────────────────────────────────────────────────────
  if (s.includes("failed to fetch") || s.includes("networkerror") || s.includes("network error"))
    return "Network error. Check your internet connection and try again.";
  if (s.includes("could not fetch scan data"))
    return "Couldn't load the scan results. Try rescanning.";

  // ── Auth / session ───────────────────────────────────────────────────────
  if (s.includes("sign in to use") || s.includes("unauthorized"))
    return "You need to sign in to use this feature.";
  if (s.includes("pro subscription") || s.includes("403"))
    return "This feature requires a Pro subscription.";

  // ── AI service ───────────────────────────────────────────────────────────
  // Out of Trojan Tokens is NOT a rate limit and must not be worded like one.
  // A rate limit clears by itself at midnight; an empty balance never does, so
  // telling the user to wait would leave them stuck. Checked first, because a
  // 402 body can also contain the word "limit".
  if (s.includes("insufficient_tokens") || s.includes("out of trojan tokens"))
    return "You're out of Trojan Tokens. Top up to continue — your run is saved and will resume where it stopped.";
  if (s.includes("rate_limit_exceeded") || (s.includes("daily") && s.includes("limit")))
    return "Daily analysis limit reached. Resets at midnight UTC.";
  if (s.includes("ai service error") || s.includes("anthropic"))
    return "The AI analysis service had a problem. Try again in a moment.";
  if (s.includes("failed to parse ai") || s.includes("unexpected response"))
    return "The AI returned an unexpected response. Try running the analysis again.";
  if (s.includes("service misconfigured"))
    return "The analysis service isn't configured correctly. Contact support.";
  if (s.includes("timed out") || s.includes("timeout") || s.includes("aborted"))
    return "The request timed out. Try again — large codebases can take longer.";

  // ── Fallback — strip developer prefixes, keep the human part ────────────
  return raw.replace(/^Error:\s*/i, "").replace(/^Scan failed:\s*/i, "").trim() || "Something went wrong. Try again.";
}

export function timeAgo(iso: string) {
  const mins = Math.floor((Date.now() - new Date(iso).getTime()) / 60000);
  if (mins < 2) return "just now";
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  return `${Math.floor(hrs / 24)}d ago`;
}

export function parseAuthCallback(url: string): Partial<UserProfile> | null {
  try {
    const u = new URL(url);
    if (u.protocol !== "trojan:" || u.hostname !== "auth") return null;
    return {
      token:        u.searchParams.get("token")         ?? undefined,
      name:         u.searchParams.get("name")          ?? undefined,
      email:        u.searchParams.get("email")         ?? undefined,
      refreshToken: u.searchParams.get("refresh_token") ?? undefined,
    };
  } catch { return null; }
}

export function greet(name: string) {
  const h = new Date().getHours();
  const p = h < 12 ? "Good morning" : h < 17 ? "Good afternoon" : "Good evening";
  return `${p}, ${name.split(" ")[0]}`;
}
export function initials(name: string) {
  return name.split(" ").filter(Boolean).map((w) => w[0]).join("").toUpperCase().slice(0, 2);
}
