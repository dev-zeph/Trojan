import { useState } from "react";

// McpConnect is the immersive Model Context Protocol connection surface for the
// Fix-with-AI view. Trojan is the MCP server; the user connects their AI editor
// (Claude Code / Cursor / Codex CLI, the MCP clients) to it. This renders that
// relationship as a live hub-and-spoke wire diagram (data flows along a wire when
// an editor is connected, the wire pulses when the editor is detected but not yet
// connected, and it is faint when the editor is not installed), a connect
// handshake sequence, and a copy-paste manual-config fallback.

export interface Editor {
  key: string;
  label: string;
  logo: string;
  desc: string;
}

interface Props {
  editors: Editor[];
  mcpStatus: Record<string, { installed: boolean; configured: boolean }>;
  onConnect: () => Promise<void>;
  busy: boolean;
}

type Phase = "idle" | "detecting" | "writing" | "verifying" | "done";

// node vertical centers in the 0..300 viewBox, one per editor slot (max 3).
const NODE_CY = [68, 150, 232];
const HUB = { x: 150, y: 150 };

export function McpConnect({ editors, mcpStatus, onConnect, busy }: Props) {
  const [phase, setPhase] = useState<Phase>("idle");
  const [showManual, setShowManual] = useState(false);

  const detected = editors.filter((e) => mcpStatus[e.key]?.installed);
  const connectedCount = editors.filter((e) => mcpStatus[e.key]?.configured).length;
  const anyConnected = connectedCount > 0;

  async function handleConnect() {
    if (busy || detected.length === 0) return;
    setPhase("detecting");
    await sleep(450);
    setPhase("writing");
    try {
      await onConnect();
    } finally {
      setPhase("verifying");
      await sleep(550);
      setPhase("done");
      await sleep(1400);
      setPhase("idle");
    }
  }

  const connecting = phase === "detecting" || phase === "writing" || phase === "verifying";

  function wireClass(e: Editor): string {
    const s = mcpStatus[e.key];
    if (connecting && s?.installed) return "mcp-wire mcp-wire-connecting";
    if (s?.configured) return "mcp-wire mcp-wire-live";
    if (s?.installed) return "mcp-wire mcp-wire-pending";
    return "mcp-wire mcp-wire-off";
  }

  return (
    <div className="mcp-connect">
      {/* ── Live connection diagram ── */}
      <div className="mcp-diagram-wrap">
        <svg className="mcp-diagram" viewBox="0 0 640 300" role="img" aria-label="Editor to Trojan MCP connections">
          <defs>
            <clipPath id="mcp-hub-clip">
              <rect x={HUB.x - 40} y={HUB.y - 40} width="80" height="80" rx="20" />
            </clipPath>
          </defs>

          {/* wires (behind nodes) */}
          {editors.slice(0, 3).map((e, i) => {
            const cy = NODE_CY[i];
            const d = `M ${HUB.x + 40} ${HUB.y} C 330 ${HUB.y} 330 ${cy} ${458} ${cy}`;
            const id = `mcp-wire-${e.key}`;
            const live = mcpStatus[e.key]?.configured;
            return (
              <g key={e.key}>
                <path id={id} d={d} className={wireClass(e)} fill="none" />
                {live && !connecting && (
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

          {/* editor nodes */}
          {editors.slice(0, 3).map((e, i) => {
            const cy = NODE_CY[i];
            const s = mcpStatus[e.key];
            const dim = !s?.installed;
            const dotClass = s?.configured ? "mcp-dot-ok" : s?.installed ? "mcp-dot-pending" : "mcp-dot-off";
            return (
              <g key={e.key} className={`mcp-node ${dim ? "mcp-node-dim" : ""} ${s?.installed && !s?.configured ? "mcp-node-clickable" : ""}`}
                onClick={() => { if (s?.installed && !s?.configured) handleConnect(); }}>
                <rect x="458" y={cy - 32} width="64" height="64" rx="16" className="mcp-node-box" />
                <image href={e.logo} x="474" y={cy - 16} width="32" height="32" preserveAspectRatio="xMidYMid meet" />
                <circle cx="516" cy={cy - 24} r="5" className={`mcp-node-dot ${dotClass}`} />
                <text x="534" y={cy - 3} className="mcp-node-label">{e.label}</text>
                <text x="534" y={cy + 13} className="mcp-node-sub">{s?.configured ? "connected" : s?.installed ? "detected" : "not installed"}</text>
              </g>
            );
          })}

          {/* Trojan hub — the actual Trojan logo, zoomed into the tile */}
          <g className="mcp-hub">
            <rect x={HUB.x - 40} y={HUB.y - 40} width="80" height="80" rx="20" className="mcp-hub-bg" />
            <image href="/logo.png" x={HUB.x - 60} y={HUB.y - 56} width="120" height="120" clipPath="url(#mcp-hub-clip)" preserveAspectRatio="xMidYMid meet" />
            <rect x={HUB.x - 40} y={HUB.y - 40} width="80" height="80" rx="20" className="mcp-hub-border" />
            <text x={HUB.x} y={HUB.y + 62} className="mcp-hub-label">Trojan</text>
            <text x={HUB.x} y={HUB.y + 78} className="mcp-hub-sub">MCP server</text>
          </g>
        </svg>

        {/* status line under the diagram */}
        <div className="mcp-statusline">
          {connecting ? (
            <span className="mcp-status-connecting">
              <span className="mcp-spin" />
              {phase === "detecting" && "Detecting editors…"}
              {phase === "writing" && "Writing MCP config…"}
              {phase === "verifying" && "Verifying connection…"}
            </span>
          ) : phase === "done" ? (
            <span className="mcp-status-ok">✓ Connected</span>
          ) : anyConnected ? (
            <span className="mcp-status-ok">✓ {connectedCount} editor{connectedCount === 1 ? "" : "s"} wired into Trojan. Ask your editor to fix a finding.</span>
          ) : detected.length > 0 ? (
            <span className="mcp-status-idle">{detected.length} editor{detected.length === 1 ? "" : "s"} detected. Connect to give {detected.length === 1 ? "it" : "them"} access to your findings.</span>
          ) : (
            <span className="mcp-status-idle">No supported editors detected. Configure one manually below.</span>
          )}
        </div>
      </div>

      {/* ── Actions ── */}
      <div className="mcp-actions">
        <button className="mcp-connect-btn" onClick={handleConnect} disabled={busy || connecting || detected.length === 0}>
          {connecting ? "Connecting…" : anyConnected ? "Reconnect editors" : detected.length > 0 ? `Connect ${detected.length} editor${detected.length === 1 ? "" : "s"}` : "No editors detected"}
        </button>
        <button className="mcp-manual-toggle" onClick={() => setShowManual((v) => !v)}>
          {showManual ? "Hide manual setup" : "Configure manually"}
        </button>
      </div>

      {showManual && <ManualConfig />}
    </div>
  );
}

function ManualConfig() {
  const blocks: { label: string; path: string; code: string }[] = [
    { label: "Claude Code", path: "~/.claude/settings.json", code: '{\n  "mcpServers": {\n    "trojan": { "command": "trojan", "args": ["mcp"] }\n  }\n}' },
    { label: "Cursor", path: "~/.cursor/mcp.json", code: '{\n  "mcpServers": {\n    "trojan": { "command": "trojan", "args": ["mcp"] }\n  }\n}' },
    { label: "Codex CLI", path: "~/.codex/config.toml", code: '[mcp_servers.trojan]\ncommand = "trojan"\nargs = ["mcp"]' },
  ];
  return (
    <div className="mcp-manual">
      <p className="mcp-manual-note">Add the <code>trojan</code> MCP server to your editor's config, then restart it. The <code>trojan</code> binary must be on your PATH.</p>
      {blocks.map((b) => <ManualBlock key={b.label} {...b} />)}
    </div>
  );
}

function ManualBlock({ label, path, code }: { label: string; path: string; code: string }) {
  const [copied, setCopied] = useState(false);
  async function copy() {
    try { await navigator.clipboard.writeText(code); setCopied(true); setTimeout(() => setCopied(false), 1400); } catch { /* ignore */ }
  }
  return (
    <div className="mcp-manual-block">
      <div className="mcp-manual-head">
        <span className="mcp-manual-label">{label}</span>
        <span className="mcp-manual-path">{path}</span>
        <button className="mcp-copy" onClick={copy}>{copied ? "Copied" : "Copy"}</button>
      </div>
      <pre className="mcp-manual-code">{code}</pre>
    </div>
  );
}

function sleep(ms: number) { return new Promise((r) => setTimeout(r, ms)); }
