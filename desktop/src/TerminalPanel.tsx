import { useEffect, useRef } from "react";
import { listen } from "@tauri-apps/api/event";
import { Terminal } from "@xterm/xterm";
import { FitAddon } from "@xterm/addon-fit";
import "@xterm/xterm/css/xterm.css";

interface TerminalPanelProps {
  height: number;
  onScan: (path: string) => void;
  onDast: (url: string) => void;
  onDeps: (path: string) => void;
}

const PROMPT = "\r\n\x1b[1;35m❯\x1b[0m ";

const HELP_TEXT = [
  "",
  "  \x1b[1;35mTrojan Terminal\x1b[0m  — available commands:",
  "  \x1b[1mscan\x1b[0m \x1b[2m<path>\x1b[0m   Full SAST · Secrets · IaC scan",
  "  \x1b[1mdast\x1b[0m \x1b[2m<url>\x1b[0m    DAST scan against a live server",
  "  \x1b[1mdeps\x1b[0m \x1b[2m<path>\x1b[0m   Dependency vulnerability scan",
  "  \x1b[1mclear\x1b[0m           Clear terminal",
  "  \x1b[1mhelp\x1b[0m            Show this help",
  "",
];

export function TerminalPanel({ height, onScan, onDast, onDeps }: TerminalPanelProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const termRef      = useRef<Terminal | null>(null);
  const fitRef       = useRef<FitAddon | null>(null);
  const lineRef      = useRef("");      // current input buffer
  const busyRef      = useRef(false);   // true while a scan is running

  // Re-fit when height changes (driven by drag resize in parent)
  useEffect(() => {
    fitRef.current?.fit();
  }, [height]);

  // One-time terminal setup
  useEffect(() => {
    if (!containerRef.current) return;

    const term = new Terminal({
      theme: {
        background:   "#0a0a0a",
        foreground:   "#cccccc",
        cursor:       "#a78bfa",
        cursorAccent: "#0a0a0a",
        selectionBackground: "rgba(167,139,250,0.25)",
        black:   "#000000", red:    "#f14c4c",
        green:   "#23d18b", yellow: "#f5f543",
        blue:    "#3b8eea", magenta:"#a78bfa",
        cyan:    "#29b8db", white:  "#e5e5e5",
        brightBlack:   "#666666", brightRed:    "#f14c4c",
        brightGreen:   "#23d18b", brightYellow: "#f5f543",
        brightBlue:    "#3b8eea", brightMagenta:"#a78bfa",
        brightCyan:    "#29b8db", brightWhite:  "#ffffff",
      },
      fontFamily: '"JetBrains Mono","Fira Code","Cascadia Code",Menlo,monospace',
      fontSize:   12,
      lineHeight: 1.5,
      cursorBlink: true,
      scrollback:  2000,
      convertEol:  true,
    });

    const fit = new FitAddon();
    term.loadAddon(fit);
    term.open(containerRef.current);
    fit.fit();
    termRef.current = term;
    fitRef.current  = fit;

    // Welcome
    term.writeln("\x1b[1;35m  Trojan Terminal\x1b[0m  \x1b[2m– type \x1b[0mhelp\x1b[2m for commands\x1b[0m");
    term.write(PROMPT);

    // ── Input handling ──────────────────────────────────────────────────────
    term.onData((data) => {
      if (busyRef.current) return;

      const code = data.charCodeAt(0);

      if (data === "\r") {                        // Enter
        const cmd = lineRef.current.trim();
        lineRef.current = "";
        term.write("\r\n");
        execCommand(cmd);
        return;
      }

      if (code === 127) {                         // Backspace
        if (lineRef.current.length > 0) {
          lineRef.current = lineRef.current.slice(0, -1);
          term.write("\b \b");
        }
        return;
      }

      if (code === 3) {                           // Ctrl+C
        lineRef.current = "";
        term.write("^C");
        term.write(PROMPT);
        return;
      }

      if (code === 12) {                          // Ctrl+L
        term.clear();
        term.write(PROMPT);
        return;
      }

      if (data.startsWith("\x1b[")) return;       // Arrow keys etc. — ignore

      if (code >= 32) {                           // Printable chars
        lineRef.current += data;
        term.write(data);
      }
    });

    // ── Command executor ────────────────────────────────────────────────────
    function execCommand(cmd: string) {
      if (!cmd) { term.write(PROMPT); return; }

      const [verb, ...rest] = cmd.split(/\s+/);
      const arg = rest.join(" ");

      switch (verb.toLowerCase()) {
        case "scan":
          if (!arg) { term.writeln("\x1b[33mUsage: scan <path>\x1b[0m"); break; }
          busyRef.current = true;
          onScan(arg);
          return;                                 // prompt shown by terminal-scan-done

        case "dast":
          if (!arg) { term.writeln("\x1b[33mUsage: dast <url>\x1b[0m"); break; }
          busyRef.current = true;
          onDast(arg);
          return;

        case "deps":
          if (!arg) { term.writeln("\x1b[33mUsage: deps <path>\x1b[0m"); break; }
          busyRef.current = true;
          onDeps(arg);
          return;

        case "clear":
        case "cls":
          term.clear();
          term.write(PROMPT);
          return;

        case "help":
          HELP_TEXT.forEach(l => term.writeln(l));
          break;

        default:
          term.writeln(`\x1b[31mUnknown command:\x1b[0m ${verb}  \x1b[2m(type \x1b[0mhelp\x1b[2m)\x1b[0m`);
      }

      term.write(PROMPT);
    }

    // ── Tauri event listeners ───────────────────────────────────────────────
    let unOutput:  (() => void) | undefined;
    let unDone:    (() => void) | undefined;

    listen<string>("terminal-output", (e) => {
      term.write(e.payload);
    }).then(fn => { unOutput = fn; });

    listen<void>("terminal-scan-done", () => {
      busyRef.current = false;
      term.write(PROMPT);
    }).then(fn => { unDone = fn; });

    // Resize observer so fit() tracks container size changes
    const ro = new ResizeObserver(() => fit.fit());
    ro.observe(containerRef.current!);

    return () => {
      unOutput?.();
      unDone?.();
      ro.disconnect();
      term.dispose();
    };
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  return (
    <div ref={containerRef} className="terminal-xterm" />
  );
}
