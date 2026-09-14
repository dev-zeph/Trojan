import { useState } from "react";
import { supabase } from "../lib/supabase";

// ── Auth form (email/password + GitHub — runs entirely inside the desktop app) ─
type AuthMode = "signin" | "signup";

export function AuthForm({
  onAuth,
  onSkip,
}: {
  onAuth: (token: string, name: string, email: string, refreshToken: string) => void;
  onSkip?: () => void;
}) {
  const [mode, setMode]               = useState<AuthMode>("signin");
  const [email, setEmail]             = useState("");
  const [password, setPassword]       = useState("");
  const [loading, setLoading]         = useState(false);
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError]             = useState<string | null>(null);
  const [success, setSuccess]         = useState<string | null>(null);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setLoading(true);
    setError(null);
    setSuccess(null);
    try {
      if (mode === "signup") {
        const { data, error } = await supabase.auth.signUp({ email, password });
        if (error) throw error;
        if (data.session) {
          const meta = data.session.user.user_metadata;
          onAuth(data.session.access_token, meta?.full_name ?? meta?.name ?? "", email, data.session.refresh_token ?? "");
        } else {
          setSuccess("Check your email to confirm your account.");
        }
      } else {
        const { data, error } = await supabase.auth.signInWithPassword({ email, password });
        if (error) throw error;
        const meta = data.session.user.user_metadata;
        onAuth(data.session.access_token, meta?.full_name ?? meta?.name ?? "", email, data.session.refresh_token ?? "");
      }
    } catch (err: unknown) {
      setError((err as { message?: string }).message ?? "Authentication failed");
    } finally {
      setLoading(false);
    }
  }

  return (
    <>
      {error   && <p className="auth-msg auth-error">{error}</p>}
      {success && <p className="auth-msg auth-success">{success}</p>}

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
          {loading ? "Please wait…" : mode === "signin" ? "Sign in" : "Create account"}
        </button>
      </form>

      <p className="auth-toggle">
        {mode === "signin" ? (
          <>Don&apos;t have an account?{" "}
            <button type="button" onClick={() => { setMode("signup"); setError(null); setSuccess(null); }}>Sign up</button>
          </>
        ) : (
          <>Already have an account?{" "}
            <button type="button" onClick={() => { setMode("signin"); setError(null); setSuccess(null); }}>Sign in</button>
          </>
        )}
      </p>

      {onSkip && (
        <button type="button" onClick={onSkip} className="ob-footer-skip">
          Continue without an account →
        </button>
      )}
    </>
  );
}
