import type { RecentProject } from "../types";
import { greet, timeAgo } from "../lib/format";

// ── Founder home ──────────────────────────────────────────────────────────
// The simple dashboard's landing page. Three things a founder can do, in
// plain language, and their latest checks. No scores or jargon here: the
// result pages explain what was found.

type McpStatus = Record<string, { installed: boolean; configured: boolean }>;

const AI_TOOL_NAMES: Record<string, string> = {
  claude_code: "Claude Code",
  cursor: "Cursor",
  codex_cli: "Codex",
};

export function FounderHome({
  name, recent, isScanning, mcpStatus, onScanCode, onTestWebsite, onConnectAI, onOpenRecent,
}: {
  name: string;
  recent: RecentProject[];
  isScanning: boolean;
  mcpStatus: McpStatus;
  onScanCode: () => void;
  onTestWebsite: () => void;
  onConnectAI: () => void;
  onOpenRecent: (r: RecentProject) => void;
}) {
  const connected = Object.entries(mcpStatus ?? {})
    .filter(([, s]) => s.configured)
    .map(([k]) => AI_TOOL_NAMES[k] ?? k);

  return (
    <div className="fh-page">
      <div className="fh-inner">
        <h2 className="fh-greeting">{greet(name)}</h2>
        <p className="fh-lead">Let's check that your product is secure and your users' information stays private.</p>

        <div className="fh-actions">
          <button className="fh-card fh-card-primary" onClick={onScanCode} disabled={isScanning}>
            <span className="fh-card-icon">
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round"><path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z" /></svg>
            </span>
            <span className="fh-card-title">Scan my code</span>
            <span className="fh-card-desc">Pick your project folder. Trojan looks for leaked passwords and keys, weak spots, and places where user data could get out. Your code never leaves your computer.</span>
            <span className="fh-card-go">{isScanning ? "A check is running…" : "Choose folder →"}</span>
          </button>

          <button className="fh-card" onClick={onTestWebsite}>
            <span className="fh-card-icon">
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="10" /><path d="M2 12h20M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10" /></svg>
            </span>
            <span className="fh-card-title">Test my website</span>
            <span className="fh-card-desc">Give Trojan your live link. It tries to break in the way a real attacker would, safely, and tells you what it got into.</span>
            <span className="fh-card-go">Enter link →</span>
          </button>

          <button className="fh-card" onClick={onConnectAI}>
            <span className="fh-card-icon">
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round"><path d="M12 2 2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5" /></svg>
            </span>
            <span className="fh-card-title">Let my AI tool fix it</span>
            <span className="fh-card-desc">
              {connected.length > 0
                ? `Connected to ${connected.join(", ")}. Ask it to "fix the issues Trojan found".`
                : "Connect the AI tool you build with, so it can read what Trojan found and fix it for you."}
            </span>
            <span className="fh-card-go">{connected.length > 0 ? "Manage →" : "Connect →"}</span>
          </button>
        </div>

        <span className="fh-section-label">YOUR LATEST CHECKS</span>
        {recent.length === 0 ? (
          <p className="fh-empty">Nothing checked yet. Start with "Scan my code" above.</p>
        ) : (
          <ul className="fh-recent">
            {recent.slice(0, 5).map((r) => (
              <li key={`${r.type}:${r.path}`}>
                <button className="fh-recent-row" onClick={() => onOpenRecent(r)}>
                  <span className="fh-recent-kind">{r.type === "dast" ? "Website" : "Code"}</span>
                  <span className="fh-recent-name">{r.type === "dast" ? r.path : r.name}</span>
                  <span className="fh-recent-when">{timeAgo(r.scannedAt)}</span>
                  <span className="fh-recent-open">See results →</span>
                </button>
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}
