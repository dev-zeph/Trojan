import { useEffect, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { getCurrentWebviewWindow } from "@tauri-apps/api/webviewWindow";
import { load } from "@tauri-apps/plugin-store";
import "./App.css";

type Screen   = "home" | "report";
type NavView  = "overview" | "sast" | "dast" | "history" | "dependencies" | "threatlab";
type ScanType = "sast" | "dast";

interface PackageAdvisory { id: string; severity: string; summary: string; fix_version?: string; }
interface PkgInfo { name: string; version: string; ecosystem: string; direct: boolean; cve_count: number; highest_severity?: string; fix_version?: string; advisories?: PackageAdvisory[]; }
interface Finding { id: string; title: string; severity: string; scanner: string; file?: string; line?: number; description?: string; }

interface AttackVector { title: string; severity: string; description: string; findings_involved: string[]; exploitability: "easy" | "moderate" | "hard"; }
interface PriorityFix  { rank: number; type: "code" | "package" | "config"; title: string; description: string; command?: string; file?: string; line?: number; finding_id?: string; }
interface ThreatLabResult {
  threat_index: number;
  grade: "A" | "B" | "C" | "D" | "F";
  verdict: string;
  attack_vectors: AttackVector[];
  priority_fixes: PriorityFix[];
  compliance_summary: string;
  key_risks: string[];
}
interface AuthStatus { loggedIn: boolean; isPro: boolean; plan: string; email?: string; }

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

const STORE_KEY      = "recent-projects";
const PROFILE_KEY    = "user-profile";
const SUPABASE_URL   = "https://dtmocojzvgsswjdsrmqr.supabase.co";

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
  {
    view: "dependencies", label: "Dependencies",
    icon: <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="5" r="2"/><circle cx="5" cy="19" r="2"/><circle cx="19" cy="19" r="2"/><path d="M12 7v3m-5.2 7.5L10 14m4 0 3.2 3.5M10 14h4"/></svg>,
  },
  {
    view: "threatlab", label: "Threat Lab",
    icon: <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"><path d="M9 3H5a2 2 0 0 0-2 2v4m6-6h10a2 2 0 0 1 2 2v4M9 3v18m0 0h10a2 2 0 0 0 2-2V9M9 21H5a2 2 0 0 1-2-2V9m0 0h18"/><path d="M14 8l-2 5h4l-2 5"/></svg>,
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
  const [packages, setPackages]           = useState<PkgInfo[]>([]);
  const [pkgExpanded, setPkgExpanded]     = useState<string | null>(null);
  const [advExpanded, setAdvExpanded]     = useState<Set<string>>(new Set());
  const [depPage, setDepPage]             = useState(0);
  const [isDepScanning, setIsDepScanning] = useState(false);
  const [depScanError, setDepScanError]   = useState<string | null>(null);
  const [depDragOver, setDepDragOver]     = useState(false);
  const [currentServerUrl, setCurrentServerUrl] = useState<string | null>(null);
  const [authStatus, setAuthStatus]       = useState<AuthStatus | null>(null);
  const [threatLabResult, setThreatLabResult] = useState<ThreatLabResult | null>(null);
  const [isLabRunning, setIsLabRunning]   = useState(false);
  const [labError, setLabError]           = useState<string | null>(null);

  const DEP_PAGE_SIZE = 50;
  const iframeRef     = useRef<HTMLIFrameElement>(null);
  const viewRef       = useRef<NavView>("overview");
  // dropHandlerRef always points to the current drop function so the stale
  // onDragDropEvent closure never holds onto an old reference.
  const dropHandlerRef = useRef<(path: string) => void>(() => {});

  const isScanning = toasts.some((t) => t.status === "scanning");

  // Keep viewRef in sync so the drag-drop callback can read current view without stale closure.
  useEffect(() => { viewRef.current = view; }, [view]);

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
      const onDeps = viewRef.current === "dependencies";
      if (event.payload.type === "enter") {
        if (onDeps) setDepDragOver(true); else setIsDragOver(true);
      } else if (event.payload.type === "leave") {
        setIsDragOver(false);
        setDepDragOver(false);
      } else if (event.payload.type === "drop") {
        setIsDragOver(false);
        setDepDragOver(false);
        if (event.payload.paths.length > 0) {
          dropHandlerRef.current(event.payload.paths[0]);
        }
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

  // Update dropHandlerRef every render so the stale drag-drop closure always calls the right function.
  dropHandlerRef.current = (path: string) => {
    if (viewRef.current === "dependencies") triggerDeps(path);
    else triggerSast(path);
  };

  function triggerDeps(path: string): void {
    if (isDepScanning) return;
    setIsDepScanning(true);
    setDepScanError(null);
    invoke<{ url: string; cachePath: string }>("scan_deps", { path })
      .then(async ({ url }) => {
        await fetchAndCachePackages(url);
        setIsDepScanning(false);
      })
      .catch((e) => {
        setDepScanError(String(e));
        setIsDepScanning(false);
      });
  }

  async function fetchAndCachePackages(serverUrl: string) {
    setCurrentServerUrl(serverUrl);
    try {
      const [scanRes, authRes] = await Promise.all([
        fetch(`${serverUrl}/api/scans/latest`),
        fetch(`${serverUrl}/api/auth/status`),
      ]);
      if (authRes.ok) {
        const a = await authRes.json();
        setAuthStatus(a as AuthStatus);
      }
      if (!scanRes.ok) return;
      const data = await scanRes.json();
      if (Array.isArray(data.packages) && data.packages.length > 0) {
        setPackages(data.packages);
        setDepPage(0);
        setPkgExpanded(null);
        setAdvExpanded(new Set());
      }
    } catch {}
  }

  async function runThreatLab() {
    if (!currentServerUrl || isLabRunning) return;
    setIsLabRunning(true);
    setLabError(null);

    try {
      // Fetch current scan data from Go server
      const scanRes = await fetch(`${currentServerUrl}/api/scans/latest`);
      if (!scanRes.ok) throw new Error("Could not fetch scan data");
      const scanData = await scanRes.json();
      const findings: Finding[] = scanData.findings ?? [];
      const pkgs: PkgInfo[] = scanData.packages ?? [];

      const token = profile?.token;
      if (!token) throw new Error("Sign in to use Threat Lab");

      const res = await fetch(`${SUPABASE_URL}/functions/v1/threat-lab`, {
        method: "POST",
        headers: {
          "Authorization": `Bearer ${token}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          project_path: scanData.project_path ?? "",
          findings,
          packages: pkgs,
        }),
      });

      if (res.status === 403) throw new Error("Threat Lab requires a Pro subscription.");
      if (res.status === 429) throw new Error("Daily Threat Lab limit reached. Try again tomorrow.");
      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error((err as { error?: string }).error ?? `Request failed (${res.status})`);
      }

      const result = await res.json() as ThreatLabResult;
      setThreatLabResult(result);
    } catch (e) {
      setLabError(String(e));
    } finally {
      setIsLabRunning(false);
    }
  }

  function exportLabTxt() {
    if (!threatLabResult) return;
    const r = threatLabResult;
    const lines = [
      "TROJAN THREAT LAB REPORT",
      "========================",
      "",
      `Threat Index: ${r.threat_index}/100  |  Grade: ${r.grade}`,
      "",
      "VERDICT",
      r.verdict,
      "",
      "KEY RISKS",
      ...r.key_risks.map(risk => `  • ${risk}`),
      "",
      "ATTACK VECTORS",
      ...r.attack_vectors.map(v => [
        `  [${v.severity.toUpperCase()}] ${v.title}  (exploitability: ${v.exploitability})`,
        `  ${v.description}`,
        `  Involves: ${v.findings_involved.join(", ")}`,
        "",
      ].join("\n")),
      "PRIORITY FIXES",
      ...r.priority_fixes.map(f => [
        `  ${f.rank}. [${f.type.toUpperCase()}] ${f.title}`,
        `     ${f.description}`,
        f.command ? `     Command: ${f.command}` : "",
        f.file ? `     File: ${f.file}${f.line ? `:${f.line}` : ""}` : "",
        "",
      ].filter(Boolean).join("\n")),
      "COMPLIANCE",
      r.compliance_summary,
    ];
    const blob = new Blob([lines.join("\n")], { type: "text/plain" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = "trojan-threat-lab.txt";
    a.click();
    URL.revokeObjectURL(a.href);
  }

  function exportLabPdf() {
    window.print();
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
        fetchAndCachePackages(url);
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
        fetchAndCachePackages(rUrl);
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
          fetchAndCachePackages(url);
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
      await s.clear();  // wipe all persisted keys (profile + recent projects)
      await s.save();   // force flush to disk so the next launch starts clean
    } catch {}
    setProfile(null);
    setRecent([]);
    setCurrentServerUrl(null);
    setAuthStatus(null);
    setThreatLabResult(null);
    setPackages([]);
  }

  async function openAuthBrowser() {
    const params = new URLSearchParams({
      redirect: "trojan://auth/callback",
      source: "desktop",
    });
    await invoke("open_auth", { url: `https://trojancli.com/login?${params}` });
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

          {/* ── Dependencies ── */}
          {view === "dependencies" && (
            <div className="content-inner">
              <div className="view-header">
                <h2 className="view-title">Dependencies</h2>
                <p className="view-desc">
                  {packages.length > 0
                    ? `${packages.length} packages · ${packages.filter(p => p.cve_count > 0).length} with known CVEs.`
                    : "Run a scan first to see your dependency health."}
                </p>
              </div>

              {/* Drop zone — always visible, even when packages are loaded */}
              <div
                className={`dep-drop-zone ${depDragOver ? "dep-drop-active" : ""} ${isDepScanning ? "dep-drop-scanning" : ""}`}
                onClick={!isDepScanning ? () => invoke<string | null>("pick_folder").then(p => p && triggerDeps(p)) : undefined}
              >
                {isDepScanning ? (
                  <>
                    <span className="dep-spinner" />
                    <p className="dep-drop-title">Scanning dependencies…</p>
                    <p className="dep-drop-sub">Running Trivy on your project</p>
                  </>
                ) : depDragOver ? (
                  <>
                    <p className="dep-drop-title">Release to scan dependencies</p>
                  </>
                ) : (
                  <>
                    <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.2" strokeLinecap="round" strokeLinejoin="round" className="dep-drop-icon">
                      <path d="M3 7c0-1.1.9-2 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V7z"/>
                    </svg>
                    <p className="dep-drop-title">Drop a project folder to check dependencies</p>
                    <p className="dep-drop-sub">Runs Trivy only — fast, no full scan</p>
                  </>
                )}
              </div>
              {depScanError && <p className="dep-error">{depScanError}</p>}

              {packages.length === 0 ? null : (() => {
                const SEV_RANK: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
                const sorted = [...packages].sort((a, b) => {
                  const ra = a.highest_severity ? (SEV_RANK[a.highest_severity] ?? 9) : 9;
                  const rb = b.highest_severity ? (SEV_RANK[b.highest_severity] ?? 9) : 9;
                  return ra - rb;
                });
                const totalPages = Math.ceil(sorted.length / DEP_PAGE_SIZE);
                const page = Math.min(depPage, totalPages - 1);
                const pageItems = sorted.slice(page * DEP_PAGE_SIZE, (page + 1) * DEP_PAGE_SIZE);
                const startNum = page * DEP_PAGE_SIZE + 1;
                const endNum   = Math.min((page + 1) * DEP_PAGE_SIZE, sorted.length);

                return (
                  <>
                    {/* Stats row */}
                    <div className="dep-stats">
                      {[
                        { label: "Total", value: packages.length },
                        { label: "Vulnerable", value: packages.filter(p => p.cve_count > 0).length },
                        { label: "Direct", value: packages.filter(p => p.direct).length },
                        { label: "Critical / High", value: packages.filter(p => p.highest_severity === "critical" || p.highest_severity === "high").length },
                      ].map((s, i) => (
                        <div key={s.label} className={`dep-stat ${i > 0 ? "dep-stat-border" : ""}`}>
                          <span className="dep-stat-label">{s.label}</span>
                          <span className="dep-stat-value">{s.value}</span>
                        </div>
                      ))}
                    </div>

                    {/* Table */}
                    <div className="dep-table">
                      <div className="dep-table-head">
                        <span className="dep-col-name">Package</span>
                        <span className="dep-col-eco">Ecosystem</span>
                        <span className="dep-col-cves">CVEs</span>
                        <span className="dep-col-sev">Severity</span>
                        <span className="dep-col-fix">Fix version</span>
                      </div>

                      {pageItems.map(pkg => {
                        const pkgKey = `${pkg.name}@${pkg.version}`;
                        const isPkgOpen = pkgExpanded === pkgKey;
                        return (
                          <div key={pkgKey} className="dep-row-wrap">
                            {/* Package row */}
                            <button
                              className={`dep-row ${pkg.cve_count > 0 ? "dep-row-clickable" : ""}`}
                              onClick={() => pkg.cve_count > 0 ? setPkgExpanded(isPkgOpen ? null : pkgKey) : undefined}
                            >
                              <span className="dep-col-name dep-pkg-name">
                                {pkg.cve_count > 0 && (
                                  <svg className={`dep-chevron ${isPkgOpen ? "dep-chevron-open" : ""}`} width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><path d="M9 5l7 7-7 7"/></svg>
                                )}
                                {!pkg.cve_count && <span className="dep-chevron-placeholder" />}
                                <span className="dep-name-mono">{pkg.name}</span>
                                <span className="dep-version-mono">{pkg.version}</span>
                                {!pkg.direct && <span className="dep-transitive">transitive</span>}
                              </span>
                              <span className="dep-col-eco dep-eco-text">{pkg.ecosystem}</span>
                              <span className={`dep-col-cves ${pkg.cve_count > 0 ? "dep-cve-count" : "dep-cve-none"}`}>
                                {pkg.cve_count > 0 ? pkg.cve_count : "—"}
                              </span>
                              <span className="dep-col-sev">
                                {pkg.highest_severity
                                  ? <span className={`dep-sev-badge dep-sev-${pkg.highest_severity}`}>{pkg.highest_severity}</span>
                                  : <span className="dep-safe">safe</span>}
                              </span>
                              <span className={`dep-col-fix dep-fix-mono ${!pkg.fix_version && pkg.cve_count > 0 ? "dep-no-fix" : ""}`}>
                                {pkg.fix_version ?? (pkg.cve_count > 0 ? "no fix" : "—")}
                              </span>
                            </button>

                            {/* Advisories (expanded per-package) */}
                            {isPkgOpen && pkg.advisories && pkg.advisories.length > 0 && (
                              <div className="dep-advisories">
                                {pkg.advisories.map(adv => {
                                  const advKey = `${pkgKey}:${adv.id}`;
                                  const isAdvOpen = advExpanded.has(advKey);
                                  return (
                                    <div key={adv.id} className="dep-advisory-wrap">
                                      <button
                                        className="dep-advisory"
                                        onClick={() => setAdvExpanded(prev => {
                                          const next = new Set(prev);
                                          if (next.has(advKey)) next.delete(advKey); else next.add(advKey);
                                          return next;
                                        })}
                                      >
                                        <svg className={`dep-chevron dep-adv-chevron ${isAdvOpen ? "dep-chevron-open" : ""}`} width="9" height="9" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><path d="M9 5l7 7-7 7"/></svg>
                                        <span className={`dep-sev-badge dep-sev-${adv.severity}`}>{adv.severity}</span>
                                        <span className="dep-adv-id">{adv.id}</span>
                                        {adv.fix_version && !isAdvOpen && (
                                          <span className="dep-adv-fix-inline">fix: {adv.fix_version}</span>
                                        )}
                                      </button>
                                      {isAdvOpen && (
                                        <div className="dep-adv-detail">
                                          {adv.summary && <p className="dep-adv-summary">{adv.summary}</p>}
                                          {adv.fix_version && (
                                            <p className="dep-adv-fix-full">
                                              <span>Fix available in version</span>
                                              <span className="dep-adv-fix-version">{adv.fix_version}</span>
                                            </p>
                                          )}
                                        </div>
                                      )}
                                    </div>
                                  );
                                })}
                              </div>
                            )}
                          </div>
                        );
                      })}
                    </div>

                    {/* Pagination */}
                    {totalPages > 1 && (
                      <div className="dep-pagination">
                        <span className="dep-page-info">
                          {startNum}–{endNum} of {sorted.length} packages
                        </span>
                        <div className="dep-page-btns">
                          <button
                            className="dep-page-btn"
                            disabled={page === 0}
                            onClick={() => { setDepPage(page - 1); setPkgExpanded(null); setAdvExpanded(new Set()); }}
                          >
                            ← Previous
                          </button>
                          <span className="dep-page-num">Page {page + 1} of {totalPages}</span>
                          <button
                            className="dep-page-btn"
                            disabled={page >= totalPages - 1}
                            onClick={() => { setDepPage(page + 1); setPkgExpanded(null); setAdvExpanded(new Set()); }}
                          >
                            Next →
                          </button>
                        </div>
                      </div>
                    )}
                  </>
                );
              })()}
            </div>
          )}

          {/* ── Threat Lab ── */}
          {view === "threatlab" && (() => {
            const isPro = authStatus?.isPro ?? false;
            const hasData = currentServerUrl != null;
            const r = threatLabResult;

            const gradeColor = (g: string) => {
              if (g === "A") return "lab-grade-a";
              if (g === "B") return "lab-grade-b";
              if (g === "C") return "lab-grade-c";
              if (g === "D") return "lab-grade-d";
              return "lab-grade-f";
            };

            return (
              <div className="content-inner lab-print-area">
                <div className="view-header">
                  <h2 className="view-title">Threat Lab</h2>
                  <p className="view-desc">AI-powered attack surface analysis combining SAST + dependency data. <span className="pro-tag">Pro</span></p>
                </div>

                {/* Run bar */}
                <div className="lab-run-bar">
                  {!hasData && (
                    <p className="lab-no-data">Run a scan first from Static Analysis or Dependencies — then come back here.</p>
                  )}
                  {hasData && !isPro && (
                    <p className="lab-no-data lab-pro-lock">
                      <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
                      Threat Lab requires a Pro subscription.
                      <button className="lab-upgrade-btn" onClick={openAuthBrowser}>Upgrade →</button>
                    </p>
                  )}
                  {hasData && isPro && (
                    <div className="lab-run-row">
                      <div>
                        <p className="lab-run-hint">Analyzes your last scan — manual trigger only, results cached 6 hours.</p>
                      </div>
                      <div className="lab-run-actions">
                        {r && (
                          <>
                            <button className="lab-export-btn" onClick={exportLabTxt} title="Export as TXT">
                              <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
                              Export TXT
                            </button>
                            <button className="lab-export-btn" onClick={exportLabPdf} title="Export as PDF">
                              <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>
                              Export PDF
                            </button>
                          </>
                        )}
                        <button
                          className={`card-btn primary-btn lab-run-btn ${isLabRunning ? "lab-btn-loading" : ""}`}
                          onClick={runThreatLab}
                          disabled={isLabRunning}
                        >
                          {isLabRunning ? (
                            <><span className="lab-spinner" /> Analysing…</>
                          ) : r ? "Re-run Analysis" : "Run Threat Lab"}
                        </button>
                      </div>
                    </div>
                  )}
                  {labError && <p className="lab-error">{labError}</p>}
                </div>

                {/* Result */}
                {r && (
                  <div className="lab-result">

                    {/* Score header */}
                    <div className="lab-score-row">
                      <div className="lab-index-wrap">
                        <div className="lab-index-ring" style={{ "--ti": r.threat_index } as React.CSSProperties}>
                          <svg viewBox="0 0 44 44" className="lab-ring-svg">
                            <circle cx="22" cy="22" r="18" className="lab-ring-track" />
                            <circle cx="22" cy="22" r="18" className="lab-ring-fill" />
                          </svg>
                          <span className="lab-index-num">{r.threat_index}</span>
                        </div>
                        <div>
                          <p className="lab-index-label">Threat Index</p>
                          <p className="lab-index-sub">0 = secure · 100 = critical</p>
                        </div>
                      </div>
                      <div className={`lab-grade ${gradeColor(r.grade)}`}>{r.grade}</div>
                      <p className="lab-verdict">{r.verdict}</p>
                    </div>

                    {/* Key risks */}
                    <section className="lab-section">
                      <h3 className="lab-section-title">Key Risks</h3>
                      <ul className="lab-risks">
                        {r.key_risks.map((risk, i) => (
                          <li key={i} className="lab-risk-item">
                            <span className="lab-risk-bullet">•</span>
                            {risk}
                          </li>
                        ))}
                      </ul>
                    </section>

                    {/* Attack vectors */}
                    <section className="lab-section">
                      <h3 className="lab-section-title">Attack Vectors</h3>
                      <div className="lab-vectors">
                        {r.attack_vectors.map((v, i) => (
                          <div key={i} className={`lab-vector lab-vector-${v.severity}`}>
                            <div className="lab-vector-head">
                              <span className={`dep-sev-badge dep-sev-${v.severity}`}>{v.severity}</span>
                              <span className="lab-vector-title">{v.title}</span>
                              <span className={`lab-exploit lab-exploit-${v.exploitability}`}>{v.exploitability}</span>
                            </div>
                            <p className="lab-vector-desc">{v.description}</p>
                            {v.findings_involved.length > 0 && (
                              <p className="lab-vector-involves">
                                <span className="lab-involves-label">Involves:</span>{" "}
                                {v.findings_involved.join(", ")}
                              </p>
                            )}
                          </div>
                        ))}
                      </div>
                    </section>

                    {/* Priority fixes */}
                    <section className="lab-section">
                      <h3 className="lab-section-title">Priority Fixes</h3>
                      <ol className="lab-fixes">
                        {r.priority_fixes.map((f) => (
                          <li key={f.rank} className="lab-fix">
                            <div className="lab-fix-head">
                              <span className={`lab-fix-type lab-fix-type-${f.type}`}>{f.type}</span>
                              <span className="lab-fix-title">{f.title}</span>
                            </div>
                            <p className="lab-fix-desc">{f.description}</p>
                            {f.command && (
                              <div className="lab-fix-cmd-wrap">
                                <code className="lab-fix-cmd">{f.command}</code>
                                <button
                                  className="lab-copy-btn"
                                  onClick={() => navigator.clipboard.writeText(f.command!)}
                                  title="Copy command"
                                >
                                  <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
                                </button>
                              </div>
                            )}
                            {f.file && (
                              <p className="lab-fix-file">
                                <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/></svg>
                                {f.file}{f.line ? `:${f.line}` : ""}
                              </p>
                            )}
                          </li>
                        ))}
                      </ol>
                    </section>

                    {/* Compliance */}
                    <section className="lab-section">
                      <h3 className="lab-section-title">Compliance Notes</h3>
                      <p className="lab-compliance">{r.compliance_summary}</p>
                    </section>

                  </div>
                )}
              </div>
            );
          })()}

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
