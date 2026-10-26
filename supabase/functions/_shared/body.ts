// Request-body helpers shared across edge functions.
//
// Supabase sits behind Cloudflare, whose WAF inspects POST bodies and rejects
// requests containing attack signatures with a 403 (and no CORS headers, so the
// browser surfaces it as a CORS error). Trojan's own SAST findings legitimately
// contain those signatures ("<script>", "' OR 1=1", "../../etc/passwd", ...), so
// clients base64-wrap the JSON payload as { "encoded": "<base64>" }. The WAF sees
// only opaque base64 and lets it through; we unwrap it here.

function decodeBase64Utf8(b64: string): string {
  const bin = atob(b64)
  const bytes = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i)
  return new TextDecoder().decode(bytes)
}

// Parse a request body that may be either raw JSON (legacy clients) or the
// base64-wrapped form. Throws on malformed input — callers handle the 400.
export async function parseBody<T>(req: Request): Promise<T> {
  const raw = await req.json()
  if (raw && typeof raw.encoded === 'string') {
    return JSON.parse(decodeBase64Utf8(raw.encoded)) as T
  }
  return raw as T
}
