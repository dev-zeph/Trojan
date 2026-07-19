import { useEffect, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { getCurrentWebviewWindow } from "@tauri-apps/api/webviewWindow";
import { load } from "@tauri-apps/plugin-store";
import { DinoGame } from "./DinoGame";
import "./App.css";

type Screen = "home" | "scanning" | "report";
type ScanType = "sast" | "dast";

interface RecentProject {
  path: string;
  name: string;
  type: ScanType;
  scannedAt: string;
}

const STORE_KEY = "recent-projects";

async function getStore() {
  return load("trojan-store.json", { autoSave: true });
}
async function loadRecent(): Promise<RecentProject[]> {
  try {
    const store = await getStore();
    return (await store.get<RecentProject[]>(STORE_KEY)) ?? [];
  } catch { return []; }
}
async function saveRecent(path: string, type: ScanType): Promise<void> {
  try {
    const store = await getStore();
    const existing = (await store.get<RecentProject[]>(STORE_KEY)) ?? [];
    const name = path.split("/").pop() ?? path;
    const entry: RecentProject = { path, name, type, scannedAt: new Date().toISOString() };
    const updated = [entry, ...existing.filter((r) => r.path !== path)].slice(0, 5);
    await store.set(STORE_KEY, updated);
  } catch {}
}
function timeAgo(iso: string): string {
  const diff = Date.now() - new Date(iso).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 2) return "just now";
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  return `${Math.floor(hrs / 24)}d ago`;
}

export default function App() {
  const [screen, setScreen] = useState<Screen>("home");
  const [scanType, setScanType] = useState<ScanType>("sast");
  const [scanLabel, setScanLabel] = useState("");
  const [reportUrl, setReportUrl] = useState("");
  const [error, setError] = useState("");
  const [isDragOver, setIsDragOver] = useState(false);
  const [recent, setRecent] = useState<RecentProject[]>([]);
  const [dastUrl, setDastUrl] = useState("");
  const iframeRef = useRef<HTMLIFrameElement>(null);

  useEffect(() => { loadRecent().then(setRecent); }, []);

  useEffect(() => {
    const appWindow = getCurrentWebviewWindow();
    let unlisten: (() => void) | undefined;
    appWindow.onDragDropEvent((event) => {
      if (event.payload.type === "enter") setIsDragOver(true);
      else if (event.payload.type === "leave") setIsDragOver(false);
      else if (event.payload.type === "drop") {
        setIsDragOver(false);
        if (event.payload.paths.length > 0) triggerSast(event.payload.paths[0]);
      }
    }).then((fn) => { unlisten = fn; });
    return () => unlisten?.();
  }, []);

  async function triggerSast(path: string) {
    setScanType("sast");
    setScanLabel(path.split("/").pop() ?? path);
    setScreen("scanning");
    setError("");
    try {
      await saveRecent(path, "sast");
      setRecent(await loadRecent());
      const url = await invoke<string>("start_scan", { path });
      setReportUrl(url);
      setScreen("report");
    } catch (e) { setError(String(e)); setScreen("home"); }
  }

  async function triggerDast(url: string) {
    if (!url.trim()) return;
    setScanType("dast");
    setScanLabel(url);
    setScreen("scanning");
    setError("");
    try {
      await saveRecent(url, "dast");
      setRecent(await loadRecent());
      const reportUrl = await invoke<string>("start_dast", { url });
      setReportUrl(reportUrl);
      setScreen("report");
    } catch (e) { setError(String(e)); setScreen("home"); }
  }

  async function handlePickFolder() {
    const selected = await invoke<string | null>("pick_folder");
    if (selected) triggerSast(selected);
  }

  function handleBack() {
    setScreen("home");
    setReportUrl("");
    setScanLabel("");
  }

  // ── Report ────────────────────────────────────────────────────────
  if (screen === "report") {
    return (
      <div className="app-shell">
        <header className="app-bar">
          <button className="back-btn" onClick={handleBack}>
            <span>←</span> Back
          </button>
          <div className="app-bar-center">
            <img src="/logo.png" alt="Trojan" className="bar-logo" />
          </div>
          <button className="rescan-btn" onClick={() =>
            scanType === "sast" ? triggerSast(scanLabel) : triggerDast(scanLabel)
          }>
            Rescan
          </button>
        </header>
        <iframe ref={iframeRef} className="report-frame" src={reportUrl} title="Trojan Security Report" />
      </div>
    );
  }

  // ── Scanning ──────────────────────────────────────────────────────
  if (screen === "scanning") {
    return (
      <div className="screen-scanning">
        <div className="scanning-top">
          <img src="/logo.png" alt="Trojan" className="scanning-logo" />
          <p className="scanning-label">
            Scanning <strong>{scanLabel}</strong>
          </p>
          <p className="scanning-sub">
            {scanType === "sast"
              ? "Running SAST · SCA · Secrets · IaC · SBOM in parallel"
              : "Running Nuclei with 6,000+ attack templates"}
          </p>
        </div>
        <div className="dino-section">
          <DinoGame />
        </div>
      </div>
    );
  }

  // ── Home ──────────────────────────────────────────────────────────
  return (
    <div className={`screen-home ${isDragOver ? "dragging" : ""}`}>
      <div className="home-inner">

        {/* Hero */}
        <div className="hero">
          <img src="/logo.png" alt="Trojan" className="hero-logo" />
          <h1 className="hero-heading">Security tools,<br />built for everyone.</h1>
          <p className="hero-sub">
            Find vulnerabilities in your code before they reach production —
            no terminal required.
          </p>
        </div>

        {error && <p className="error-msg">{error}</p>}

        {/* Scan cards */}
        <div className="scan-cards">

          {/* SAST card */}
          <div className={`scan-card ${isDragOver ? "drag-over" : ""}`}>
            <div className="scan-card-header">
              <div className="scan-badge sast-badge">SAST · SCA · Secrets · IaC</div>
              <h2 className="scan-card-title">Static Analysis</h2>
              <p className="scan-card-desc">
                Scan a local project folder for code vulnerabilities, leaked secrets,
                dependency CVEs, and infrastructure misconfigurations.
              </p>
            </div>
            <div className="scan-card-body">
              <div className="drop-zone">
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" className="drop-icon">
                  <path d="M3 7c0-1.1.9-2 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V7z"/>
                </svg>
                <span>Drop project folder here</span>
              </div>
              <button className="card-btn primary-btn" onClick={handlePickFolder}>
                Choose folder
              </button>
            </div>
            <ul className="scan-features">
              <li><span className="feat-dot" />Semgrep — code vulnerabilities</li>
              <li><span className="feat-dot" />Trivy — dependency CVEs</li>
              <li><span className="feat-dot" />Gitleaks — leaked secrets</li>
              <li><span className="feat-dot" />Checkov — IaC misconfigs</li>
              <li><span className="feat-dot" />Syft — SBOM generation</li>
            </ul>
          </div>

          {/* DAST card */}
          <div className="scan-card">
            <div className="scan-card-header">
              <div className="scan-badge dast-badge">DAST · Runtime</div>
              <h2 className="scan-card-title">Dynamic Analysis</h2>
              <p className="scan-card-desc">
                Scan a running local server for runtime vulnerabilities — CORS issues,
                exposed endpoints, missing headers, and 6,000+ attack patterns.
              </p>
            </div>
            <div className="scan-card-body">
              <form
                className="dast-form"
                onSubmit={(e) => { e.preventDefault(); triggerDast(dastUrl); }}
              >
                <input
                  className="dast-input"
                  type="url"
                  placeholder="http://localhost:3000"
                  value={dastUrl}
                  onChange={(e) => setDastUrl(e.target.value)}
                />
                <button type="submit" className="card-btn primary-btn">
                  Scan URL
                </button>
              </form>
            </div>
            <ul className="scan-features">
              <li><span className="feat-dot dast-dot" />Nuclei — 6,618 templates</li>
              <li><span className="feat-dot dast-dot" />AI-generated attack patterns</li>
              <li><span className="feat-dot dast-dot" />CORS &amp; header checks</li>
              <li><span className="feat-dot dast-dot" />Exposed endpoint detection</li>
              <li><span className="feat-dot dast-dot pro-tag" />Pro required</li>
            </ul>
          </div>

        </div>

        {/* Recent */}
        {recent.length > 0 && (
          <section className="recent-section">
            <h3 className="recent-heading">Recent</h3>
            <ul className="recent-list">
              {recent.map((r) => (
                <li key={r.path}>
                  <button
                    className="recent-item"
                    onClick={() => r.type === "sast" ? triggerSast(r.path) : triggerDast(r.path)}
                  >
                    <div className="recent-left">
                      <span className={`recent-type-badge ${r.type}-badge-sm`}>
                        {r.type.toUpperCase()}
                      </span>
                      <div>
                        <span className="recent-name">{r.name}</span>
                        <span className="recent-path">{r.path}</span>
                      </div>
                    </div>
                    <div className="recent-right">
                      <span className="recent-time">{timeAgo(r.scannedAt)}</span>
                      <span className="recent-cta">Scan →</span>
                    </div>
                  </button>
                </li>
              ))}
            </ul>
          </section>
        )}

      </div>
    </div>
  );
}
