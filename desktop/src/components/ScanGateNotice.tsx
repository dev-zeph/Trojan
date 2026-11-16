import type { ScanGate } from "../lib/scanGate";

type Blocked = Exclude<ScanGate, { ok: true }>;

interface Props {
  gate: Blocked;
  onSignIn: () => void;
  onTopUp: () => void;
  onClose: () => void;
}

/** Shown instead of starting a code scan that cannot run. Used by both dashboards. */
export function ScanGateNotice({ gate, onSignIn, onTopUp, onClose }: Props) {
  const signedOut = gate.reason === "signed_out";
  return (
    <div className="auth-overlay" onClick={onClose} role="dialog" aria-modal="true" aria-label="Cannot scan yet">
      <div className="auth-modal" onClick={(e) => e.stopPropagation()} style={{ gap: 16, maxWidth: 420 }}>
        <h2 className="auth-modal-title">{signedOut ? "Sign in to scan" : "Not enough tokens"}</h2>
        <p style={{ margin: 0, font: "400 13px/1.55 var(--font-sans)", color: "var(--sb-muted)" }}>
          {gate.message}
        </p>
        <div style={{ display: "flex", gap: 8 }}>
          <button className="lab-upgrade-btn" onClick={signedOut ? onSignIn : onTopUp}>
            {signedOut ? "Sign in" : "Top up"}
          </button>
          <button className="lab-upgrade-btn" style={{ opacity: 0.7 }} onClick={onClose}>Close</button>
        </div>
      </div>
    </div>
  );
}
