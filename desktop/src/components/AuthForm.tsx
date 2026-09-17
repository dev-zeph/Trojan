import { useState } from "react";
import { openUrl } from "@tauri-apps/plugin-opener";
import { supabase } from "../lib/supabase";
import { MARKETING_URL } from "../constants";

// ── Auth form (sign-in only — runs entirely inside the desktop app) ─
// Sign-up happens on the website instead: the desktop app has no email
// verification handling, plan/token onboarding, or terms acceptance, so it
// hands new-account creation off to trojancli.com/login (which supports both
// sign-in and sign-up) rather than faking a sign-up flow in-app.

export function AuthForm({
  onAuth,
  onSkip,
}: {
  onAuth: (token: string, name: string, email: string, refreshToken: string) => void;
  onSkip?: () => void;
}) {
  const [email, setEmail]             = useState("");
  const [password, setPassword]       = useState("");
  const [loading, setLoading]         = useState(false);
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError]             = useState<string | null>(null);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setLoading(true);
    setError(null);
    try {
      const { data, error } = await supabase.auth.signInWithPassword({ email, password });
      if (error) throw error;
      const meta = data.session.user.user_metadata;
      onAuth(data.session.access_token, meta?.full_name ?? meta?.name ?? "", email, data.session.refresh_token ?? "");
    } catch (err: unknown) {
      setError((err as { message?: string }).message ?? "Authentication failed");
    } finally {
      setLoading(false);
    }
  }

  function handleCreateAccount() {
    openUrl(`${MARKETING_URL}/login`).catch(() => {});
  }

  return (
    <>
      {error && <p className="auth-msg auth-error">{error}</p>}

      <form onSubmit={handleSubmit} className="ob-form">
        <div className="ob-field">
          <label className="ob-label ob-label-mono">EMAIL</label>
          <input
            type="email" required value={email} autoFocus
            onChange={(e) => setEmail(e.target.value)}
            placeholder="you@example.com" className="ob-input"
          />
        </div>
        <div className="ob-field">
          <label className="ob-label ob-label-mono">PASSWORD</label>
          <div style={{ position: "relative" }}>
            <input
              type={showPassword ? "text" : "password"} required value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="••••••••" className="ob-input" style={{ paddingRight: 36 }}
            />
            <button
              type="button"
              onClick={() => setShowPassword(!showPassword)}
              style={{ position: "absolute", right: 8, top: "50%", transform: "translateY(-50%)", background: "none", border: "none", cursor: "pointer", padding: 4, color: "inherit", opacity: 0.5 }}
              title={showPassword ? "Hide password" : "Show password"}
            >
              {showPassword ? (
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94"/><path d="M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19"/><line x1="1" y1="1" x2="23" y2="23"/><path d="M14.12 14.12a3 3 0 1 1-4.24-4.24"/></svg>
              ) : (
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
              )}
            </button>
          </div>
        </div>
        <button type="submit" disabled={loading} className="ob-btn auth-submit-btn">
          {loading && <span className="auth-spinner" />}
          {loading ? "Please wait…" : "Sign in"}
        </button>
      </form>

      <p className="auth-toggle">
        Don&apos;t have an account?{" "}
        <button type="button" onClick={handleCreateAccount}>Create one on trojancli.com</button>
      </p>

      {onSkip && (
        <button type="button" onClick={onSkip} className="ob-footer-skip">
          Continue without an account →
        </button>
      )}
    </>
  );
}
