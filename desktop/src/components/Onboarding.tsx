import { useState } from "react";
import { saveProfile } from "../lib/store";
import type { UserProfile } from "../types";
import { AuthForm } from "./AuthForm";

// ── Onboarding ────────────────────────────────────────────────────────────
export function Onboarding({ onDone }: { onDone: (p: UserProfile) => void }) {
  const [showLocal, setShowLocal] = useState(false);
  const [name, setName]           = useState("");
  const [busy, setBusy]           = useState(false);

  function handleAuth(token: string, authName: string, email: string, refreshToken: string) {
    const p: UserProfile = {
      name:  authName || email.split("@")[0] || "User",
      email,
      token,
      refreshToken,
    };
    saveProfile(p).then(() => onDone(p));
  }

  async function handleLocalSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!name.trim()) return;
    setBusy(true);
    const p: UserProfile = { name: name.trim(), email: "" };
    await saveProfile(p);
    onDone(p);
  }

  return (
    <div className="ob-split">

      {/* ── Left dark brand panel ── */}
      <div className="ob-left">
        {/* Centered brand block */}
        <div className="ob-left-center">
          <img src="/logo.png" alt="Trojan" className="ob-left-logo" />
          <span className="ob-left-wordmark">TROJAN</span>
          <p className="ob-left-tagline">
            Industry-standard vulnerability scanners in one tool.
          </p>
        </div>

        {/* Bottom metadata */}
        <div className="ob-left-bottom">
          <div className="ob-left-features">SAST · DAST · SECRETS · DEPENDENCIES · AI THREAT ANALYSIS</div>
          <div className="ob-left-ver">v0.1.0</div>
        </div>
      </div>

      {/* ── Right auth panel ── */}
      <div className="ob-right">
        <div className="ob-right-card">

          {/* Corner + marks */}
          <i className="corner-mark cm-tl">+</i>
          <i className="corner-mark cm-tr">+</i>
          <i className="corner-mark cm-bl">+</i>
          <i className="corner-mark cm-br">+</i>

          {!showLocal ? (
            <>
              <span className="ob-right-title">Sign in</span>

              <AuthForm onAuth={handleAuth} onSkip={undefined} />

              <div className="ob-footer-sep">
                <button type="button" className="ob-footer-skip" onClick={() => setShowLocal(true)}>
                  Continue without an account →
                </button>
              </div>
            </>
          ) : (
            <>
              <span className="ob-right-title">Set up your workspace</span>

              <form className="ob-form" onSubmit={handleLocalSubmit}>
                <div className="ob-field">
                  <label className="ob-label">NAME</label>
                  <input
                    className="ob-input" placeholder="Your name" autoFocus
                    value={name} onChange={(e) => setName(e.target.value)}
                  />
                </div>
                <button className="ob-btn" type="submit" disabled={!name.trim() || busy}>
                  {busy ? "Setting up…" : "Continue →"}
                </button>
              </form>

              <div className="ob-footer-sep">
                <button type="button" className="ob-footer-skip" onClick={() => setShowLocal(false)}>
                  ← Back to sign in
                </button>
                <span className="ob-footer-note">Sign in at any time from the sidebar.</span>
              </div>
            </>
          )}
        </div>
      </div>

    </div>
  );
}
