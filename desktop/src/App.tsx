import { useEffect, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { getCurrentWebviewWindow } from "@tauri-apps/api/webviewWindow";
import { load } from "@tauri-apps/plugin-store";
import "./App.css";

type Screen   = "home" | "report";
type NavView  = "overview" | "sast" | "dast" | "history";
type ScanType = "sast" | "dast";

interface RecentProject { path: string; name: string; type: ScanType; scannedAt: string; reportUrl?: string; cachePath?: string; }
interface UserProfile   { name: string; email: string; token?: string; }
interface Toast {
  id: string;
  label: string;
  type: ScanType;
  path: string;
  status: "scanning" | "done" | "error";
  reportUrl?: string;
  cachePath?: string;
  error?: string;
}

const STORE_KEY   = "recent-projects";
const PROFILE_KEY = "user-profile";

async function getStore() { return load("trojan-store.json", { autoSave: true }); }
async function loadProfile(): Promise<UserProfile | null> {
  try { const s = await getStore(); return (await s.get<UserProfile>(PROFILE_KEY)) ?? null; }
  catch { return null; }
}
async function saveProfile(p: UserProfile) {
  try { const s = await getStore(); await s.set(PROFILE_KEY, p); } catch {}
}
async function loadRecent(): Promise<RecentProject[]> {
  try {
    const s = await getStore();
    const raw = (await s.get<RecentProject[]>(STORE_KEY)) ?? [];
    return raw.filter((r) => r && r.path && r.type);
  } catch { return []; }
}
async function saveRecent(path: string, type: ScanType) {
  try {
    const s = await getStore();
    const existing = (await s.get<RecentProject[]>(STORE_KEY)) ?? [];
    const name = path.split("/").pop() ?? path;
    const prev = existing.find((r) => r.path === path);
    const entry: RecentProject = { path, name, type, scannedAt: new Date().toISOString(), reportUrl: prev?.reportUrl };
    await s.set(STORE_KEY, [entry, ...existing.filter((r) => r.path !== path)].slice(0, 10));
  } catch {}
}
async function updateRecentUrl(path: string, reportUrl: string) {
  try {
    const s = await getStore();
    const existing = (await s.get<RecentProject[]>(STORE_KEY)) ?? [];
    await s.set(STORE_KEY, existing.map((r) => r.path === path ? { ...r, reportUrl } : r));
  } catch {}
}
async function updateRecentCachePath(path: string, cachePath: string) {
  try {
    const s = await getStore();
    const existing = (await s.get<RecentProject[]>(STORE_KEY)) ?? [];
    await s.set(STORE_KEY, existing.map((r) => r.path === path ? { ...r, cachePath } : r));
  } catch {}
}

function timeAgo(iso: string) {
  const mins = Math.floor((Date.now() - new Date(iso).getTime()) / 60000);
  if (mins < 2) return "just now";
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  return `${Math.floor(hrs / 24)}d ago`;
}

function parseAuthCallback(url: string): Partial<UserProfile> | null {
  try {
    const u = new URL(url);
    if (u.protocol !== "trojan:" || u.hostname !== "auth") return null;
    return {
      token: u.searchParams.get("token") ?? undefined,
      name:  u.searchParams.get("name")  ?? undefined,
      email: u.searchParams.get("email") ?? undefined,
    };
  } catch { return null; }
}

function greet(name: string) {
  const h = new Date().getHours();
  const p = h < 12 ? "Good morning" : h < 17 ? "Good afternoon" : "Good evening";
  return `${p}, ${name.split(" ")[0]}`;
}
function initials(name: string) {
  return name.split(" ").filter(Boolean).map((w) => w[0]).join("").toUpperCase().slice(0, 2);
}

// ── Onboarding ────────────────────────────────────────────────────────────
function Onboarding({ onDone, onSignIn }: { onDone: (p: UserProfile) => void; onSignIn: () => void }) {
  const [name, setName]   = useState("");
  const [email, setEmail] = useState("");
  const [busy, setBusy]   = useState(false);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    if (!name.trim()) return;
    setBusy(true);
    const p = { name: name.trim(), email: email.trim() };
    await saveProfile(p);
    onDone(p);
  }

  return (
    <div className="screen-onboarding">
      <div className="ob-card">
        <img src="/logo.png" alt="Trojan" className="ob-logo" />

        <div className="ob-text">
          <h1 className="ob-heading">Create your workspace</h1>
          <p className="ob-sub">Sign in or set up a local workspace to get started.</p>
        </div>

        <button className="ob-signin-btn" type="button" onClick={onSignIn}>
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"><path d="M15 3h4a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2h-4"/><polyline points="10 17 15 12 10 7"/><line x1="15" y1="12" x2="3" y2="12"/></svg>
          Sign in with your Trojan account
        </button>

        <div className="ob-divider">or continue locally</div>

        <form className="ob-form" onSubmit={submit}>
          <div className="ob-field">
            <label className="ob-label">Email</label>
            <input
              className="ob-input" type="email" placeholder="you@company.com"
              value={email} onChange={(e) => setEmail(e.target.value)} autoFocus
            />
          </div>
          <div className="ob-field">
            <label className="ob-label">Name</label>
            <input
              className="ob-input" placeholder="Your name"
              value={name} onChange={(e) => setName(e.target.value)}
            />
          </div>
          <button className="ob-btn" type="submit" disabled={!name.trim() || busy}>
            {busy ? "Setting up…" : "Continue offline →"}
          </button>
        </form>
      </div>
    </div>
  );
}

// ── Nav icons ─────────────────────────────────────────────────────────────
const NAV: { view: NavView; label: string; icon: React.ReactNode }[] = [
  {
    view: "overview", label: "Overview",
    icon: <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"><rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/></svg>,
  },
  {
    view: "sast", label: "Static Analysis",
    icon: <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"><polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/></svg>,
  },
  {
    view: "dast", label: "Dynamic Analysis",
    icon: <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>,
  },
  {
    view: "history", label: "Scan History",
    icon: <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>,
  },
];

// ── App ───────────────────────────────────────────────────────────────────
export default function App() {
  const [profileLoaded, setProfileLoaded] = useState(false);
  const [profile, setProfile]             = useState<UserProfile | null>(null);
  const [screen, setScreen]               = useState<Screen>("home");
  const [view, setView]                   = useState<NavView>("overview");
  const [scanPath, setScanPath]           = useState("");
  const [scanType, setScanType]           = useState<ScanType>("sast");
  const [reportUrl, setReportUrl]         = useState("");
  const [isDragOver, setIsDragOver]       = useState(false);
  const [recent, setRecent]               = useState<RecentProject[]>([]);
  const [dastUrl, setDastUrl]             = useState("");
  const [toasts, setToasts]               = useState<Toast[]>([]);
  const iframeRef = useRef<HTMLIFrameElement>(null);

  const isScanning = toasts.some((t) => t.status === "scanning");

  useEffect(() => {
    Promise.all([loadProfile(), loadRecent()]).then(([p, r]) => {
      setProfile(p); setRecent(r); setProfileLoaded(true);
    });
  }, []);

  // ── Deep-link auth callback ────────────────────────────────────────
  useEffect(() => {
    let unlisten: (() => void) | undefined;
    listen<string[]>("deep-link-received", async (event) => {
      for (const url of event.payload) {
        const parsed = parseAuthCallback(url);
        if (parsed?.token) {
          const current = await loadProfile();
          const p: UserProfile = {
            name:  parsed.name  || current?.name  || "User",
            email: parsed.email || current?.email || "",
            token: parsed.token,
          };
          await saveProfile(p);
          setProfile(p);
          return;
        }
      }
    }).then((fn) => { unlisten = fn; });
    return () => unlisten?.();
  }, []);

  useEffect(() => {
    const appWindow = getCurrentWebviewWindow();
    let unlisten: (() => void) | undefined;
    appWindow.onDragDropEvent((event) => {
      if (event.payload.type === "enter")       setIsDragOver(true);
      else if (event.payload.type === "leave")  setIsDragOver(false);
      else if (event.payload.type === "drop") {
        setIsDragOver(false);
        if (event.payload.paths.length > 0) triggerSast(event.payload.paths[0]);
      }
    }).then((fn) => { unlisten = fn; });
    return () => unlisten?.();
  }, []);

  function addToast(id: string, label: string, type: ScanType, path: string): void {
    setToasts((prev) => [...prev, { id, label, type, path, status: "scanning" }]);
  }
  function updateToastDone(id: string, reportUrl: string, cachePath?: string): void {
    setToasts((prev) => prev.map((t) => t.id === id ? { ...t, status: "done", reportUrl, cachePath } : t));
  }
  function updateToastError(id: string, error: string): void {
    setToasts((prev) => prev.map((t) => t.id === id ? { ...t, status: "error", error } : t));
  }
  function dismissToast(id: string): void {
    setToasts((prev) => prev.filter((t) => t.id !== id));
  }

  function triggerSast(path: string): void {
    if (isScanning) return;
    const id = crypto.randomUUID();
    const label = path.split("/").pop() ?? path;
    addToast(id, label, "sast", path);

    saveRecent(path, "sast").then(() => loadRecent().then(setRecent));

    invoke<{ url: string; cachePath: string }>("start_scan", { path })
      .then(async ({ url, cachePath }) => {
        updateToastDone(id, url, cachePath);
        await updateRecentUrl(path, url);
        await updateRecentCachePath(path, cachePath);
        setRecent(await loadRecent());
      })
      .catch((e) => updateToastError(id, String(e)));
  }

  function triggerDast(url: string): void {
    if (!url.trim() || isScanning) return;
    const id = crypto.randomUUID();
    addToast(id, url, "dast", url);

    saveRecent(url, "dast").then(() => loadRecent().then(setRecent));

    invoke<{ url: string; cachePath: string }>("start_dast", { url })
      .then(async ({ url: rUrl, cachePath }) => {
        updateToastDone(id, rUrl, cachePath);
        await updateRecentUrl(url, rUrl);
        await updateRecentCachePath(url, cachePath);
        setRecent(await loadRecent());
      })
      .catch((e) => updateToastError(id, String(e)));
  }

  function openReport(url: string, path: string, type: ScanType): void {
    setScanPath(path);
    setScanType(type);
    setReportUrl(url);
    setScreen("report");
  }

  function openRecent(r: RecentProject): void {
    if (r.cachePath) {
      // Re-serve cached findings — starts a fresh server, no zombie processes
      const id = crypto.randomUUID();
      addToast(id, r.name, r.type, r.path);
      invoke<string>("serve_scan", { cachePath: r.cachePath })
        .then((url) => {
          updateToastDone(id, url, r.cachePath);
          openReport(url, r.path, r.type);
          dismissToast(id);
        })
        .catch((e) => updateToastError(id, String(e)));
    } else if (!isScanning) {
      r.type === "sast" ? triggerSast(r.path) : triggerDast(r.path);
    }
    // If isScanning and no cache path, do nothing — scan is already running
  }

  async function logout() {
    try {
      const s = await getStore();
      await s.delete(PROFILE_KEY);
    } catch {}
    setProfile(null);
  }

  async function openAuthBrowser() {
    const params = new URLSearchParams({
      redirect: "trojan://auth/callback",
      source: "desktop",
    });
    await invoke("open_auth", { url: `https://trojancli.com/auth/login?${params}` });
  }

  async function handlePickFolder() {
    const selected = await invoke<string | null>("pick_folder");
    if (selected) triggerSast(selected);
  }

  // ── Gate renders ─────────────────────────────────────────────────────
  if (!profileLoaded) return null;

  if (!profile) return <Onboarding onDone={(p) => setProfile(p)} onSignIn={openAuthBrowser} />;

  if (screen === "report") return (
    <div className="app-shell">
      <header className="app-bar">
        <button className="back-btn" onClick={() => { setScreen("home"); setReportUrl(""); setScanPath(""); }}>
          <span>←</span> Back
        </button>
        <div className="app-bar-center"><img src="/logo.png" alt="Trojan" className="bar-logo" /></div>
        <button className="rescan-btn" onClick={() =>
          scanType === "sast" ? triggerSast(scanPath) : triggerDast(scanPath)
        }>Rescan</button>
      </header>
      <iframe ref={iframeRef} className="report-frame" src={reportUrl} title="Trojan Security Report" />
    </div>
  );

  // ── Main layout ───────────────────────────────────────────────────────
  return (
    <div className="app-layout">

      {/* Sidebar */}
      <aside className="sidebar">
        <div className="sidebar-logo-wrap">
          <img src="/logo.png" alt="Trojan" className="sidebar-logo" />
        </div>

        <nav className="sidebar-nav">
          {NAV.map(({ view: v, label, icon }) => (
            <button
              key={v}
              className={`sidebar-nav-item ${view === v ? "active" : ""}`}
              onClick={() => setView(v)}
            >
              <span className="nav-icon">{icon}</span>
              {label}
            </button>
          ))}
        </nav>

        <div className="sidebar-user">
          <div className="sidebar-avatar">{initials(profile.name)}</div>
          <div className="sidebar-user-info">
            <span className="sidebar-user-name">
              {profile.name}
              {profile.token && <span className="auth-badge">Synced</span>}
            </span>
            {profile.email && <span className="sidebar-user-email">{profile.email}</span>}
          </div>
          <button className="logout-btn" onClick={logout} title="Sign out">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
              <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/>
              <polyline points="16 17 21 12 16 7"/>
              <line x1="21" y1="12" x2="9" y2="12"/>
            </svg>
          </button>
        </div>
      </aside>

      {/* Right panel */}
      <div className="app-content">

        {/* Topbar */}
        <header className="topbar">
          <span className="topbar-title">{NAV.find((n) => n.view === view)?.label}</span>
          <div className="topbar-right">
            <div className="topbar-avatar" title={profile.name}>{initials(profile.name)}</div>
          </div>
        </header>

        {/* Content */}
        <main className="content-area">

          {/* ── Overview ── */}
          {view === "overview" && (
            <div className="content-inner">
              <div className="overview-hero">
                <h2 className="overview-greeting">{greet(profile.name)}</h2>
                <p className="overview-sub">
                  {recent.length > 0
                    ? `${recent.length} scan${recent.length > 1 ? "s" : ""} on record · last run ${timeAgo(recent[0].scannedAt)}`
                    : "Run your first scan below to get started."}
                </p>
              </div>

              <div className="ov-cards">
                {/* SAST card */}
                <div className={`scan-tip-wrap ${isScanning ? "scanning-active" : ""}`}>
                <div className={`ov-card ${isDragOver && !isScanning ? "drag-over" : ""} ${isScanning ? "scan-locked" : ""}`}>
                  <div>
                    <div className="ov-badge sast-badge">SAST · SCA · Secrets · IaC</div>
                    <h3 className="ov-card-title">Static Analysis</h3>
                    <p className="ov-card-desc">
                      Scan a local project for code vulnerabilities, leaked secrets,
                      dependency CVEs, and infrastructure misconfigurations.
                    </p>
                  </div>
                  <div className="ov-card-actions">
                    <div className="drop-hint">
                      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><path d="M3 7c0-1.1.9-2 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V7z"/></svg>
                      {isScanning ? "Scan in progress…" : "Drop folder anywhere"}
                    </div>
                    <button className="card-btn primary-btn" onClick={handlePickFolder} disabled={isScanning}>
                      Choose folder
                    </button>
                  </div>
                </div>
                </div>{/* /scan-tip-wrap */}

                {/* DAST card */}
                <div className={`scan-tip-wrap ${isScanning ? "scanning-active" : ""}`}>
                <div className={`ov-card ${isScanning ? "scan-locked" : ""}`}>
                  <div>
                    <div className="ov-badge dast-badge">DAST · Runtime</div>
                    <h3 className="ov-card-title">Dynamic Analysis</h3>
                    <p className="ov-card-desc">
                      Scan a running local server for runtime vulnerabilities —
                      CORS issues, exposed endpoints, missing headers, and 6,000+ attack patterns.
                    </p>
                  </div>
                  <form onSubmit={(e) => { e.preventDefault(); triggerDast(dastUrl); }}>
                    <input
                      className="dast-input"
                      type="url"
                      placeholder="http://localhost:3000"
                      value={dastUrl}
                      onChange={(e) => setDastUrl(e.target.value)}
                      disabled={isScanning}
                    />
                    <button type="submit" className="card-btn primary-btn" style={{ marginTop: 8 }} disabled={isScanning}>
                      Scan URL
                    </button>
                  </form>
                </div>
                </div>{/* /scan-tip-wrap */}
              </div>

              {recent.length > 0 && (
                <section>
                  <h3 className="section-label">Recent Scans</h3>
                  <ul className="recent-list">
                    {recent.slice(0, 5).map((r) => (
                      <li key={r.path}>
                        <button
                          className={`recent-item ${isScanning && !r.cachePath ? "scan-locked recent-locked" : ""}`}
                          onClick={() => openRecent(r)}
                          title={isScanning && !r.cachePath ? "A scan is already in progress" : undefined}
                        >
                          <div className="recent-left">
                            <span className={`recent-type-badge ${r.type}-badge-sm`}>{(r.type ?? "sast").toUpperCase()}</span>
                            <div>
                              <span className="recent-name">{r.name}</span>
                              <span className="recent-path">{r.path}</span>
                            </div>
                          </div>
                          <div className="recent-right">
                            <span className="recent-time">{timeAgo(r.scannedAt)}</span>
                            <span className="recent-cta">{r.cachePath ? "View →" : "Scan →"}</span>
                          </div>
                        </button>
                      </li>
                    ))}
                  </ul>
                </section>
              )}
            </div>
          )}

          {/* ── SAST ── */}
          {view === "sast" && (
            <div className="content-inner">
              <div className="view-header">
                <h2 className="view-title">Static Analysis</h2>
                <p className="view-desc">Scan a local project for vulnerabilities, secrets, and misconfigurations.</p>
              </div>

              <div className={`scan-tip-wrap ${isScanning ? "scanning-active" : ""}`}>
              <div
                className={`sast-drop-zone ${isDragOver && !isScanning ? "drag-active" : ""} ${isScanning ? "scan-locked" : ""}`}
                onClick={!isScanning ? handlePickFolder : undefined}
              >
                {isScanning ? (
                  <>
                    <span className="sast-scanning-spinner" />
                    <p className="sast-drop-title">Scan in progress…</p>
                    <p className="sast-drop-or">Check the notification in the bottom-right</p>
                  </>
                ) : (
                  <>
                    <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.2" strokeLinecap="round" strokeLinejoin="round" className="sast-drop-icon">
                      <path d="M3 7c0-1.1.9-2 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V7z"/>
                    </svg>
                    <p className="sast-drop-title">Drop your project folder here</p>
                    <p className="sast-drop-or">— or —</p>
                    <button className="card-btn primary-btn sast-choose-btn" onClick={(e) => { e.stopPropagation(); handlePickFolder(); }}>
                      Choose folder
                    </button>
                  </>
                )}
              </div>
              </div>{/* /scan-tip-wrap */}

              <div>
                <h3 className="section-label">What gets scanned</h3>
                <div className="feature-grid">
                  {[
                    { name: "Semgrep",   desc: "SAST code vulnerability patterns" },
                    { name: "Trivy",     desc: "Dependency CVEs & OS packages" },
                    { name: "Gitleaks", desc: "Leaked secrets & API keys" },
                    { name: "Checkov",  desc: "IaC misconfigurations" },
                    { name: "Syft",     desc: "Software Bill of Materials (SBOM)" },
                  ].map((f) => (
                    <div key={f.name} className="feature-chip">
                      <span className="chip-dot" />
                      <div><span className="chip-name">{f.name}</span><span className="chip-desc">{f.desc}</span></div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* ── DAST ── */}
          {view === "dast" && (
            <div className="content-inner">
              <div className="view-header">
                <h2 className="view-title">Dynamic Analysis</h2>
                <p className="view-desc">Scan a running server for runtime vulnerabilities using Nuclei's 6,000+ templates.</p>
              </div>

              <div className={`scan-tip-wrap ${isScanning ? "scanning-active" : ""}`}>
              <div className={`dast-panel ${isScanning ? "scan-locked" : ""}`}>
                <label className="dast-field-label">Target URL</label>
                <form className="dast-panel-form" onSubmit={(e) => { e.preventDefault(); triggerDast(dastUrl); }}>
                  <input
                    className="dast-input dast-input-lg"
                    type="url"
                    placeholder="http://localhost:3000"
                    value={dastUrl}
                    onChange={(e) => setDastUrl(e.target.value)}
                    disabled={isScanning}
                    autoFocus
                  />
                  <button type="submit" className="card-btn primary-btn dast-panel-btn" disabled={isScanning}>
                    {isScanning ? "Scan in progress…" : "Start Dynamic Scan"}
                  </button>
                </form>
              </div>
              </div>{/* /scan-tip-wrap */}

              <div>
                <h3 className="section-label">What gets scanned</h3>
                <div className="feature-grid">
                  {[
                    { name: "Nuclei",             desc: "6,618 community attack templates",   pro: false },
                    { name: "CORS checks",         desc: "Cross-origin misconfiguration",      pro: false },
                    { name: "Header analysis",    desc: "Missing security headers",           pro: false },
                    { name: "Endpoint detection", desc: "Exposed admin & API routes",         pro: false },
                    { name: "AI patterns",        desc: "AI-generated attack chains",         pro: true  },
                  ].map((f) => (
                    <div key={f.name} className={`feature-chip ${f.pro ? "chip-pro" : ""}`}>
                      <span className={`chip-dot ${f.pro ? "chip-dot-purple" : ""}`} />
                      <div>
                        <span className="chip-name">
                          {f.name} {f.pro && <span className="pro-tag">Pro</span>}
                        </span>
                        <span className="chip-desc">{f.desc}</span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* ── History ── */}
          {view === "history" && (
            <div className="content-inner">
              <div className="view-header">
                <h2 className="view-title">Scan History</h2>
                <p className="view-desc">
                  {recent.length > 0
                    ? `${recent.length} scan${recent.length !== 1 ? "s" : ""} on record. Click any entry to re-run.`
                    : "No scans yet."}
                </p>
              </div>

              {recent.length === 0 ? (
                <div className="empty-state">
                  <p>Run your first scan from Overview or Static / Dynamic Analysis.</p>
                </div>
              ) : (
                <ul className="history-list">
                  {recent.map((r) => (
                    <li key={r.path}>
                      <button className="history-item" onClick={() => openRecent(r)}>
                        <div className="recent-left">
                          <span className={`recent-type-badge ${r.type}-badge-sm`}>{(r.type ?? "sast").toUpperCase()}</span>
                          <div>
                            <span className="recent-name">{r.name}</span>
                            <span className="recent-path">{r.path}</span>
                          </div>
                        </div>
                        <div className="recent-right">
                          <span className="recent-time">{timeAgo(r.scannedAt)}</span>
                          <span className="recent-cta">{r.cachePath ? "View →" : "Scan →"}</span>
                        </div>
                      </button>
                    </li>
                  ))}
                </ul>
              )}
            </div>
          )}

        </main>
      </div>

      {/* ── Toast container ── */}
      {toasts.length > 0 && (
        <div className="toast-container">
          {toasts.map((t) => (
            <div key={t.id} className={`toast toast-${t.status}`}>
              <div className="toast-icon">
                {t.status === "scanning" && <span className="toast-spinner" />}
                {t.status === "done" && (
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><polyline points="20 6 9 17 4 12"/></svg>
                )}
                {t.status === "error" && (
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
                )}
              </div>
              <div className="toast-body">
                <p className="toast-label">
                  {t.status === "scanning" && `Scanning ${t.label}…`}
                  {t.status === "done"     && t.label}
                  {t.status === "error"    && `Failed: ${t.label}`}
                </p>
                <p className="toast-sub">
                  {t.status === "scanning" && (t.type === "sast" ? "Running SAST · SCA · Secrets · IaC" : "Running Nuclei templates…")}
                  {t.status === "done"     && (t.type === "sast" ? "SAST scan complete" : "DAST scan complete")}
                  {t.status === "error"    && (t.error ?? "Scan failed")}
                </p>
                {t.status === "done" && t.reportUrl && (
                  <button
                    className="toast-view-btn"
                    onClick={() => { openReport(t.reportUrl!, t.path, t.type); dismissToast(t.id); }}
                  >
                    View scan report →
                  </button>
                )}
              </div>
              {t.status !== "scanning" && (
                <button className="toast-dismiss" onClick={() => dismissToast(t.id)} title="Dismiss">
                  <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
                </button>
              )}
            </div>
          ))}
        </div>
      )}

    </div>
  );
}
