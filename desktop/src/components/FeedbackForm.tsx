import { useState } from "react";
import { SUPABASE_URL } from "../constants";
import { encodeBody } from "../lib/supabase";
import { friendlyError } from "../lib/format";

// ── In-app feedback ───────────────────────────────────────────────────────
//
// The point of this form is to catch a reaction at the moment it happens. That
// shapes two decisions:
//
//   1. One textarea and four buttons. Every extra field is another reason to
//      close the window instead of typing.
//   2. Version and screen are attached automatically. "The scan broke" is
//      nearly useless without knowing which build and where, and no tester
//      should be asked to look either of them up.

const CATEGORIES = [
  { key: "bug",       label: "Bug" },
  { key: "idea",      label: "Idea" },
  { key: "confusing", label: "Confusing" },
  { key: "other",     label: "Other" },
] as const;

type CategoryKey = typeof CATEGORIES[number]["key"];

/** Matches the CHECK constraint in migration 021 and the edge function. */
const MAX_MESSAGE = 4000;

export function FeedbackForm({
  getToken,
  appVersion,
  view,
  onSent,
}: {
  /** Same fresh-token getter every other network call in the app uses. */
  getToken: () => Promise<string | null>;
  appVersion: string;
  view: string;
  onSent: () => void;
}) {
  const [category, setCategory] = useState<CategoryKey>("bug");
  const [message, setMessage]   = useState("");
  const [loading, setLoading]   = useState(false);
  const [error, setError]       = useState<string | null>(null);
  const [sent, setSent]         = useState(false);

  const trimmed = message.trim();

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!trimmed || loading) return;

    setLoading(true);
    setError(null);
    try {
      const token = await getToken();
      if (!token) throw new Error("Sign in to send feedback.");

      const res = await fetch(`${SUPABASE_URL}/functions/v1/feedback`, {
        method: "POST",
        headers: { "Authorization": `Bearer ${token}`, "Content-Type": "application/json" },
        // encodeBody, not raw JSON. Bug reports quote the exact payloads Trojan
        // finds ("<script>", "' OR 1=1"), and Cloudflare's WAF 403s those in a
        // plain body -- which surfaces as an unexplained CORS failure.
        body: JSON.stringify({ encoded: encodeBody({ category, message: trimmed, appVersion, view }) }),
      });

      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(err.error ?? `Request failed (${res.status})`);
      }

      setSent(true);
      // Long enough to read the confirmation, short enough not to be in the way.
      setTimeout(onSent, 1100);
    } catch (err: unknown) {
      setError(friendlyError((err as { message?: string }).message ?? "Could not send feedback."));
    } finally {
      setLoading(false);
    }
  }

  if (sent) {
    return (
      <p className="auth-msg auth-success" style={{ margin: 0 }}>
        Thank you. This goes straight to the person building it.
      </p>
    );
  }

  return (
    <>
      {error && <p className="auth-msg auth-error">{error}</p>}

      <form onSubmit={handleSubmit} className="ob-form">
        <div className="ob-field">
          <label className="ob-label ob-label-mono">WHAT KIND</label>
          <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
            {CATEGORIES.map(({ key, label }) => {
              const active = category === key;
              return (
                <button
                  key={key}
                  type="button"
                  onClick={() => setCategory(key)}
                  aria-pressed={active}
                  style={{
                    flex: 1,
                    minWidth: 68,
                    padding: "7px 10px",
                    font: "600 12px var(--font-sans)",
                    cursor: "pointer",
                    // The accent marks the active state and nothing else here.
                    background: active ? "var(--primary)" : "transparent",
                    color: active ? "var(--primary-fg)" : "var(--muted-fg)",
                    border: `1px solid ${active ? "var(--primary)" : "var(--border)"}`,
                    borderRadius: "var(--radius)",
                  }}
                >
                  {label}
                </button>
              );
            })}
          </div>
        </div>

        <div className="ob-field">
          <label className="ob-label ob-label-mono">WHAT HAPPENED</label>
          <textarea
            required
            autoFocus
            value={message}
            maxLength={MAX_MESSAGE}
            onChange={(e) => setMessage(e.target.value)}
            placeholder="Blunt is useful. What did you expect, and what happened instead?"
            className="ob-input profile-textarea profile-textarea--tall"
          />
        </div>

        <button type="submit" disabled={loading || !trimmed} className="ob-btn auth-submit-btn">
          {loading && <span className="auth-spinner" />}
          {loading ? "Sending…" : "Send feedback"}
        </button>
      </form>

      <p style={{ font: "11px var(--font-mono)", color: "var(--muted-fg)", margin: "10px 0 0", textAlign: "center" }}>
        Sent with v{appVersion} and the {view} screen attached.
      </p>
    </>
  );
}
