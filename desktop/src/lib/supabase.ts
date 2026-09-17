import { invoke } from "@tauri-apps/api/core";
import { createClient } from "@supabase/supabase-js";
import { SUPABASE_URL, SUPABASE_ANON_KEY } from "../constants";

export const supabase = createClient(SUPABASE_URL, SUPABASE_ANON_KEY);

// Decode a JWT payload without verifying the signature (verification happens
// server-side on every API call). Returns null on any parse error.
export function decodeJWT(token: string): Record<string, unknown> | null {
  try {
    const b64 = token.split(".")[1]?.replace(/-/g, "+").replace(/_/g, "/");
    if (!b64) return null;
    return JSON.parse(atob(b64));
  } catch { return null; }
}

// Base64-encode a value's JSON. Edge-function request bodies are wrapped as
// { encoded } so Cloudflare's WAF (in front of Supabase) doesn't false-positive
// on attack signatures inside SAST findings ("<script>", "' OR 1=1", path
// traversal, ...) and reject the request with a 403. The functions unwrap it
// transparently via _shared/body.ts. UTF-8 safe (btoa alone is not).
export function encodeBody(value: unknown): string {
  const bytes = new TextEncoder().encode(JSON.stringify(value));
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin);
}

// Write the access token to ~/.trojan/config.json so the Go sidecar and its
// embedded report UI treat the desktop session as authenticated.
export async function syncAuthToGoConfig(token: string, email: string, refreshToken = ""): Promise<void> {
  try {
    const claims = decodeJWT(token);
    if (!claims) return;
    const exp = (claims.exp as number) * 1000;
    const expiresAt = new Date(exp).toISOString();
    const sub = (claims.subscription_status as string | undefined) ?? "";
    const isPro = sub === "pro" || sub === "team";
    await invoke("sync_auth", { token, email, expiresAt, isPro, refreshToken });
  } catch {}
}
