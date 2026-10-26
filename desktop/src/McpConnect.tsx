import { useState } from "react";
import type { McpToolStatus } from "./types";
import { timeAgo } from "./lib/format";

// McpConnect is the connection surface for the Fix-with-AI view. While the
// desktop app is open it hosts Trojan's MCP server on this computer; each AI
// tool (Claude Code / Cursor / Codex, the MCP clients) is pointed at it with
// its own Connect button. The diagram shows real state: a wire only goes live
// once that tool has actually talked to Trojan, not merely been configured.

export interface Editor {
  key: string;
  label: string;
  logo: string;
  desc: string;
}

interface Props {
  editors: Editor[];
  mcpStatus: Record<string, McpToolStatus>;
  // Resolves to an error message, or null on success.
  onConnect: (tool: string) => Promise<string | null>;
  signedIn: boolean;
  onSignIn: () => void;
}

// What a founder types into their AI tool once connected.
export const FIX_PROMPT = "Fix the security issues Trojan found in this project";

// How each tool picks up a new connection.
const RESTART_HINT: Record<string, string> = {
  claude_code: "Start a new Claude Code session in your project folder.",
  cursor: "Restart Cursor, then open your project folder.",
  codex_cli: "Start a new Codex session in your project folder.",
};

// node vertical centers in the 0..300 viewBox, one per editor slot (max 3).
const NODE_CY = [68, 150, 232];
const HUB = { x: 150, y: 150 };

type ToolState = "missing" | "ready" | "waiting" | "live";

function toolState(s: McpToolStatus | undefined): ToolState {
  if (s?.configured && s.lastUsed) return "live";
  if (s?.configured) return "waiting";
  if (s?.installed) return "ready";
  return "missing";
}

export function McpConnect({ editors, mcpStatus, onConnect, signedIn, onSignIn }: Props) {
  const [busy, setBusy]     = useState<string | null>(null);
  const [errors, setErrors] = useState<Record<string, string>>({});

  async function connect(tool: string) {
    if (busy || !signedIn) return;
    setBusy(tool);
    const err = await onConnect(tool);
    setErrors((e) => ({ ...e, [tool]: err ?? "" }));
    setBusy(null);
  }

  const states = editors.map((e) => toolState(mcpStatus[e.key]));
  const liveCount = states.filter((s) => s === "live").length;

  function wireClass(e: Editor, st: ToolState): string {
    if (busy === e.key) return "mcp-wire mcp-wire-connecting";
    if (st === "live") return "mcp-wire mcp-wire-live";
    if (st === "waiting" || st === "ready") return "mcp-wire mcp-wire-pending";
    return "mcp-wire mcp-wire-off";
  }

  return (
    <div className="mcp-connect">
      {/* ── Live connection diagram ── */}
      <div className="mcp-diagram-wrap">
        <svg className="mcp-diagram" viewBox="0 0 640 300" role="img" aria-label="AI tool to Trojan connections">
          {editors.slice(0, 3).map((e, i) => {
            const cy = NODE_CY[i];
            const d = `M ${HUB.x + 40} ${HUB.y} C 330 ${HUB.y} 330 ${cy} ${458} ${cy}`;
            const id = `mcp-wire-${e.key}`;
            const live = states[i] === "live" && busy !== e.key;
            return (
              <g key={e.key}>
                <path id={id} d={d} className={wireClass(e, states[i])} fill="none" />
                {live && (
                  <>
                    <circle r="3" className="mcp-particle">
                      <animateMotion dur="1.9s" repeatCount="indefinite"><mpath href={`#${id}`} /></animateMotion>
                    </circle>
                    <circle r="3" className="mcp-particle">
                      <animateMotion dur="1.9s" begin="0.95s" repeatCount="indefinite"><mpath href={`#${id}`} /></animateMotion>
                    </circle>
                  </>
                )}
              </g>
            );
          })}

          {editors.slice(0, 3).map((e, i) => {
            const cy = NODE_CY[i];
            const st = states[i];
            const dotClass = st === "live" ? "mcp-dot-ok" : st === "missing" ? "mcp-dot-off" : "mcp-dot-pending";
            const sub = st === "live" ? "connected" : st === "waiting" ? "waiting for first use" : st === "ready" ? "not connected" : "not installed";
            return (
              <g key={e.key} className={`mcp-node ${st === "missing" ? "mcp-node-dim" : ""}`}>
                <rect x="458" y={cy - 32} width="64" height="64" rx="16" className="mcp-node-box" />
                <image href={e.logo} x="474" y={cy - 16} width="32" height="32" preserveAspectRatio="xMidYMid meet" />
                <circle cx="516" cy={cy - 24} r="5" className={`mcp-node-dot ${dotClass}`} />
                <text x="534" y={cy - 3} className="mcp-node-label">{e.label}</text>
                <text x="534" y={cy + 13} className="mcp-node-sub">{sub}</text>
              </g>
            );
          })}

          <g className="mcp-hub">
            <rect x={HUB.x - 40} y={HUB.y - 40} width="80" height="80" rx="20" className="mcp-hub-bg" />
            <image href="/logo-mark.png" x={HUB.x - 33} y={HUB.y - 24} width="66" height="48" preserveAspectRatio="xMidYMid meet" />
            <rect x={HUB.x - 40} y={HUB.y - 40} width="80" height="80" rx="20" className="mcp-hub-border" />
            <text x={HUB.x} y={HUB.y + 62} className="mcp-hub-label">Trojan</text>
            <text x={HUB.x} y={HUB.y + 78} className="mcp-hub-sub">on this computer</text>
          </g>
        </svg>

        <div className="mcp-statusline">
          {liveCount > 0
            ? <span className="mcp-status-ok">✓ Your AI tool can see what Trojan found. Keep this app open while you work.</span>
            : <span className="mcp-status-idle">Connect the AI tool you build with. Trojan stays on your computer while it works.</span>}
        </div>
      </div>

      {!signedIn && (
        <div className="mcp-gate">
          <span>Sign in to connect your AI tool to Trojan.</span>
          <button className="mcp-connect-btn" onClick={onSignIn}>Sign in</button>
        </div>
      )}

      {/* ── One row per tool ── */}
      <div className="mcp-tools">
        {editors.map((e, i) => {
          const st = states[i];
          const s = mcpStatus[e.key];
          const err = errors[e.key];
          return (
            <div key={e.key} className={`mcp-tool mcp-tool-${st}`}>
              <img src={e.logo} alt="" className="mcp-tool-logo" />
              <div className="mcp-tool-body">
                <span className="mcp-tool-name">{e.label}</span>
                <span className="mcp-tool-status">
                  {st === "missing" && "Not found on this computer."}
                  {st === "ready" && e.desc}
                  {st === "waiting" && RESTART_HINT[e.key]}
                  {st === "live" && s?.lastUsed && (
                    <>Connected · last seen {timeAgo(s.lastUsed)}{s.project ? ` in ${s.project.split("/").pop()}` : ""}</>
                  )}
                </span>
                {st === "waiting" && <CopyPrompt />}
                {err && <span className="mcp-tool-error">{err}</span>}
              </div>
              {(st === "ready" || st === "waiting" || st === "live") && (
                <button
                  className={st === "ready" ? "mcp-connect-btn" : "mcp-reconnect"}
                  onClick={() => connect(e.key)}
                  disabled={!signedIn || busy !== null}
                >
                  {busy === e.key ? "Connecting…" : st === "ready" ? "Connect" : "Reconnect"}
                </button>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}

// The one sentence a founder needs, with a copy button.
export function CopyPrompt() {
  const [copied, setCopied] = useState(false);
  async function copy() {
    try { await navigator.clipboard.writeText(FIX_PROMPT); setCopied(true); setTimeout(() => setCopied(false), 1400); } catch { /* ignore */ }
  }
  return (
    <span className="mcp-prompt">
      Then ask it: <q>{FIX_PROMPT}</q>
      <button className="mcp-copy" onClick={copy}>{copied ? "Copied" : "Copy"}</button>
    </span>
  );
}
