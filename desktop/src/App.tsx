import { useCallback, useEffect, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { getCurrentWebviewWindow } from "@tauri-apps/api/webviewWindow";
import { load } from "@tauri-apps/plugin-store";
import { createClient } from "@supabase/supabase-js";
import { TerminalPanel } from "./TerminalPanel";
import { PrintCertificate } from "./PrintCertificate";
import "./App.css";

type NavView  = "overview" | "sast" | "dast" | "history" | "dependencies" | "threatlab" | "profile" | "report";
type ScanType = "sast" | "dast";

interface PackageAdvisory { id: string; severity: string; summary: string; fix_version?: string; }
interface PkgInfo { name: string; version: string; ecosystem: string; direct: boolean; cve_count: number; highest_severity?: string; fix_version?: string; advisories?: PackageAdvisory[]; }
interface Finding { id: string; title: string; severity: string; scanner: string; file?: string; line?: number; description?: string; }
interface ScanSummary { critical: number; high: number; medium: number; low: number; info: number; total: number; scannedAt: string; }

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
interface UserProfile   { name: string; email: string; token?: string; refreshToken?: string; familiarity?: number; aboutYou?: string; avatarDataUrl?: string; }
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
const TERMINAL_KEY   = "terminal-prefs";
const SUPABASE_URL   = "https://dtmocojzvgsswjdsrmqr.supabase.co";
const SUPABASE_ANON_KEY = "sb_publishable_U1qvJb7QebxgH5_0HCMYJQ_jKBybATQ";

const supabase = createClient(SUPABASE_URL, SUPABASE_ANON_KEY);

// Decode a JWT payload without verifying the signature (verification happens
// server-side on every API call). Returns null on any parse error.
function decodeJWT(token: string): Record<string, unknown> | null {
  try {
    const b64 = token.split(".")[1]?.replace(/-/g, "+").replace(/_/g, "/");
    if (!b64) return null;
    return JSON.parse(atob(b64));
  } catch { return null; }
}

// Write the access token to ~/.trojan/config.json so the Go sidecar and its
// embedded report UI treat the desktop session as authenticated.
async function syncAuthToGoConfig(token: string, email: string, refreshToken = ""): Promise<void> {
  try {
    const claims = decodeJWT(token);
    if (!claims) return;
    const exp = (claims.exp as number) * 1000;
    const expiresAt = new Date(exp).toISOString();
    const sub = (claims.subscription_status as string | undefined) ?? "";
    const isPro = sub === "pro" || sub === "team";
    await invoke("sync_auth", { token, email, expiresAt, isPro, refreshToken });
  } catch {}
}

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

async function deleteRecentEntry(path: string): Promise<RecentProject[]> {
  try {
    const s = await getStore();
    const existing = (await s.get<RecentProject[]>(STORE_KEY)) ?? [];
    const updated = existing.filter((r) => r.path !== path);
    await s.set(STORE_KEY, updated);
    await s.save();
    return updated;
  } catch { return []; }
}

// Maps raw internal error strings (from Rust/Go/network) to user-friendly messages.
// Applied at every error surface so neither persona sees developer-facing text.
function friendlyError(raw: string): string {
  const s = raw.toLowerCase();

  // ── Sidecar / spawn ──────────────────────────────────────────────────────
  if (s.includes("sidecar not found") || s.includes("sidecar"))
    return "Could not start the scanner. Try reinstalling Trojan.";
  if (s.includes("spawn failed") || s.includes("spawn"))
    return "The scanner couldn't launch. Restart the app and try again.";

  // ── Scan process exits ───────────────────────────────────────────────────
  if (s.includes("no scanners installed") || s.includes("trojan init"))
    return "Scanners aren't set up yet. Open a terminal and run: trojan init";
  if (s.includes("process exited") || s.includes("scan failed"))
    return "The scan stopped unexpectedly. Try running it again.";
  if (s.includes("server failed to start") || s.includes("could not start"))
    return "The scan report server failed to start. Restart the app and try again.";

  // ── Network ──────────────────────────────────────────────────────────────
  if (s.includes("failed to fetch") || s.includes("networkerror") || s.includes("network error"))
    return "Network error. Check your internet connection and try again.";
  if (s.includes("could not fetch scan data"))
    return "Couldn't load the scan results. Try rescanning.";

  // ── Auth / session ───────────────────────────────────────────────────────
  if (s.includes("sign in to use") || s.includes("unauthorized"))
    return "You need to sign in to use this feature.";
  if (s.includes("pro subscription") || s.includes("403"))
    return "This feature requires a Pro subscription.";

  // ── AI service ───────────────────────────────────────────────────────────
  if (s.includes("rate_limit_exceeded") || (s.includes("daily") && s.includes("limit")))
    return "Daily analysis limit reached. Resets at midnight UTC.";
  if (s.includes("ai service error") || s.includes("anthropic"))
    return "The AI analysis service had a problem. Try again in a moment.";
  if (s.includes("failed to parse ai") || s.includes("unexpected response"))
    return "The AI returned an unexpected response. Try running the analysis again.";
  if (s.includes("service misconfigured"))
    return "The analysis service isn't configured correctly. Contact support.";
  if (s.includes("timed out") || s.includes("timeout") || s.includes("aborted"))
    return "The request timed out. Try again — large codebases can take longer.";

  // ── Fallback — strip developer prefixes, keep the human part ────────────
  return raw.replace(/^Error:\s*/i, "").replace(/^Scan failed:\s*/i, "").trim() || "Something went wrong. Try again.";
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
      token:        u.searchParams.get("token")         ?? undefined,
      name:         u.searchParams.get("name")          ?? undefined,
      email:        u.searchParams.get("email")         ?? undefined,
      refreshToken: u.searchParams.get("refresh_token") ?? undefined,
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

// ── Auth form (email/password + GitHub — runs entirely inside the desktop app) ─
type AuthMode = "signin" | "signup";

function AuthForm({
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
  const [githubLoading, setGithubLoading] = useState(false);
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

  async function handleGitHub() {
    setGithubLoading(true);
    setError(null);
    try {
      // Start the one-shot TCP callback server and get its port.
      const port = await invoke<number>("start_auth_callback");

      // Ask Supabase for the GitHub OAuth URL directly — skips the website login
      // page entirely. The code exchange still happens via /auth/desktop-callback
      // on the website, which then bounces the token to our local TCP server.
      //
      // The TCP callback server (start_auth_callback) is the production auth approach.
      const { data, error } = await supabase.auth.signInWithOAuth({
        provider: "github",
        options: {
          redirectTo: `https://trojancli.com/auth/desktop-callback?redirect=${encodeURIComponent(`http://127.0.0.1:${port}/callback`)}`,
          skipBrowserRedirect: true,
        },
      });
      if (error) throw error;
      if (data.url) await invoke("open_auth", { url: data.url });
      // githubLoading stays true until the browser completes OAuth and the
      // parent's auth-callback Tauri event fires (which causes this component
      // to unmount, naturally resetting all state).
    } catch (err: unknown) {
      setError((err as { message?: string }).message ?? "GitHub login failed");
      setGithubLoading(false);
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
          <input
            type="password" required value={password}
            onChange={(e) => setPassword(e.target.value)}
            placeholder="••••••••" className="ob-input"
          />
        </div>
        <button type="submit" disabled={loading || githubLoading} className="ob-btn auth-submit-btn">
          {loading && <span className="auth-spinner" />}
          {loading ? "Please wait…" : mode === "signin" ? "Sign in" : "Create account"}
        </button>
      </form>

      <div className="ob-divider">or</div>

      <button type="button" onClick={handleGitHub} disabled={loading || githubLoading} className="ob-signin-btn">
        {githubLoading ? (
          <span className="auth-spinner auth-spinner-dark" />
        ) : (
          <svg viewBox="0 0 24 24" width="14" height="14" fill="currentColor" aria-hidden="true">
            <path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0 0 24 12c0-6.63-5.37-12-12-12z" />
          </svg>
        )}
        {githubLoading ? "Opening browser…" : "Continue with GitHub"}
      </button>

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

// ── Onboarding ────────────────────────────────────────────────────────────
function Onboarding({ onDone }: { onDone: (p: UserProfile) => void }) {
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
        <div className="ob-left-traffic">
          <span className="tl-dot tl-red" />
          <span className="tl-dot tl-amber" />
          <span className="tl-dot tl-green" />
        </div>

        {/* Centered brand block */}
        <div className="ob-left-center">
          <img src="/logo.png" alt="Trojan" className="ob-left-logo" />
          <span className="ob-left-wordmark">TROJAN</span>
          <p className="ob-left-tagline">
            A local-first security workstation for production codebases. Scans run on this machine — nothing leaves it.
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
              <span className="ob-access-label">OPERATOR ACCESS</span>
              <span className="ob-right-title">Sign in</span>

              <AuthForm onAuth={handleAuth} onSkip={undefined} />

              <div className="ob-footer-sep">
                <button type="button" className="ob-footer-skip" onClick={() => setShowLocal(true)}>
                  Continue without an account →
                </button>
                <span className="ob-footer-note">Creates a local workspace. Scans stay on this machine.</span>
              </div>
            </>
          ) : (
            <>
              <span className="ob-access-label">LOCAL WORKSPACE</span>
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

// ── Corner marks helper ───────────────────────────────────────────────────
const CM = () => (
  <div className="corner-marks">
    <i className="corner-mark cm-tl">+</i>
    <i className="corner-mark cm-tr">+</i>
    <i className="corner-mark cm-bl">+</i>
    <i className="corner-mark cm-br">+</i>
  </div>
);

// ── Nav icons — exact paths from design file ───────────────────────────
const NAV: { view: NavView; label: string; icon: React.ReactNode; pro?: boolean }[] = [
  {
    view: "overview", label: "Overview",
    icon: <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"><path d="M12 14l4-4 M3.34 19a10 10 0 1 1 17.32 0"/></svg>,
  },
  {
    view: "sast", label: "Static Analysis",
    icon: <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"><path d="M16 18l6-6-6-6 M8 6l-6 6 6 6"/></svg>,
  },
  {
    view: "dast", label: "Dynamic Analysis",
    icon: <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"><path d="M12 2a10 10 0 1 0 0 20 10 10 0 0 0 0-20 M2 12h20 M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10"/></svg>,
  },
  {
    view: "history", label: "Scan History",
    icon: <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"><path d="M3 12a9 9 0 1 0 9-9 9.75 9.75 0 0 0-6.74 2.74L3 8 M3 3v5h5 M12 7v5l4 2"/></svg>,
  },
  {
    view: "dependencies", label: "Dependencies",
    icon: <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"><path d="M21 8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16Z M3.3 7l8.7 5 8.7-5 M12 22V12"/></svg>,
  },
  {
    view: "threatlab", label: "Threat Lab", pro: true,
    icon: <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"><path d="M10 2v7.53a2 2 0 0 1-.21.9L4.72 20.55a1 1 0 0 0 .9 1.45h12.76a1 1 0 0 0 .9-1.45l-5.07-10.12a2 2 0 0 1-.21-.9V2 M8.5 2h7 M7 16h10"/></svg>,
  },
  {
    view: "profile", label: "Profile",
    icon: <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="8" r="4"/><path d="M4 20c0-4 3.6-7 8-7s8 3 8 7"/></svg>,
  },
];

// ── App ───────────────────────────────────────────────────────────────────
export default function App() {
  const [profileLoaded, setProfileLoaded] = useState(false);
  const [profile, setProfile]             = useState<UserProfile | null>(null);
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
  const [scanSummary, setScanSummary]         = useState<ScanSummary | null>(null);
  const [threatLabResult, setThreatLabResult] = useState<ThreatLabResult | null>(null);
  const [isLabRunning, setIsLabRunning]   = useState(false);
  const [labError, setLabError]           = useState<string | null>(null);
  const [showAuthForm, setShowAuthForm]   = useState(false);
  const [historyFilter, setHistoryFilter] = useState<"all" | "sast" | "dast">("all");
  const [staleCaches, setStaleCaches]     = useState<Set<string>>(new Set());
  const [terminalOpen, setTerminalOpen]   = useState(true);
  const [terminalHeight, setTerminalHeight] = useState(220);
  const [sessionExpired, setSessionExpired] = useState(false);

  const DEP_PAGE_SIZE = 50;
  const iframeRef     = useRef<HTMLIFrameElement>(null);
  const viewRef       = useRef<NavView>("overview");
  // dropHandlerRef always points to the current drop function so the stale
  // onDragDropEvent closure never holds onto an old reference.
  const dropHandlerRef = useRef<(path: string) => void>(() => {});
  // profileRef gives closures (event listeners, async callbacks) always-current profile.
  const profileRef = useRef<UserProfile | null>(null);

  const isScanning = toasts.some((t) => t.status === "scanning");

  // Keep viewRef in sync so the drag-drop callback can read current view without stale closure.
  useEffect(() => { viewRef.current = view; }, [view]);
  useEffect(() => { profileRef.current = profile; }, [profile]);

  // Persist terminal layout so it survives app restarts.
  useEffect(() => {
    getStore().then(s => s.set(TERMINAL_KEY, { open: terminalOpen, height: terminalHeight })).catch(() => {});
  }, [terminalOpen, terminalHeight]);

  // Validate cache paths whenever history changes. Any entry whose file no
  // longer exists on disk is added to staleCaches and shown with a badge.
  useEffect(() => {
    const withCache = recent.filter(r => r.cachePath);
    if (withCache.length === 0) { setStaleCaches(new Set()); return; }
    Promise.all(
      withCache.map(r =>
        invoke<boolean>("check_cache_exists", { path: r.cachePath! })
          .then(exists => ({ key: r.path, stale: !exists }))
          .catch(() => ({ key: r.path, stale: true }))
      )
    ).then(results => {
      setStaleCaches(new Set(results.filter(r => r.stale).map(r => r.key)));
    });
  }, [recent]);

  useEffect(() => {
    async function init() {
      const [p, r] = await Promise.all([loadProfile(), loadRecent()]);
      // Restore terminal layout prefs from previous session
      try {
        const s = await getStore();
        const prefs = await s.get<{ open: boolean; height: number }>(TERMINAL_KEY);
        if (prefs) {
          setTerminalOpen(prefs.open);
          setTerminalHeight(prefs.height);
        }
      } catch {}
      setRecent(r);

      let activeProfile = p;

      if (p?.email) {
        // 1. Try getSession() first — Supabase's client manages rotation
        //    automatically in localStorage, which survives Tauri restarts.
        //    This avoids the 400 caused by reusing an already-rotated token.
        try {
          const { data: sessionData } = await supabase.auth.getSession();
          if (sessionData.session) {
            activeProfile = {
              ...p,
              token:        sessionData.session.access_token,
              refreshToken: sessionData.session.refresh_token ?? p?.refreshToken ?? "",
            };
            await saveProfile(activeProfile);
          } else if (p?.refreshToken) {
            // 2. No live session in localStorage (e.g. GitHub OAuth path that
            //    bypassed the Supabase client) — try explicit refresh.
            const { data: refreshData } = await supabase.auth.refreshSession({
              refresh_token: p.refreshToken,
            });
            if (refreshData.session) {
              activeProfile = {
                ...p,
                token:        refreshData.session.access_token,
                refreshToken: refreshData.session.refresh_token ?? p.refreshToken,
              };
              await saveProfile(activeProfile);
            }
          }
        } catch {}
      }

      setProfile(activeProfile);
      setProfileLoaded(true);
      if (activeProfile?.token && activeProfile.email) {
        syncAuthToGoConfig(activeProfile.token, activeProfile.email, activeProfile.refreshToken ?? "");
      }
    }
    init();
  }, []);

  // ── Token refresh ─────────────────────────────────────────────────
  // Single source of truth for getting a valid access token before any
  // Supabase API call. Always calls getSession() so the client can rotate
  // the token silently. Falls back to explicit refreshSession() if needed.
  // On success, syncs the refreshed token back to profile state + Go config.
  // On failure, sets sessionExpired so the banner appears.
  const getFreshToken = useCallback(async (): Promise<string | null> => {
    const p = profileRef.current;
    if (!p?.email) return null;

    try {
      const { data: s } = await supabase.auth.getSession();
      if (s.session?.access_token) {
        const tok = s.session.access_token;
        const ref = s.session.refresh_token ?? p.refreshToken ?? "";
        // Sync back if the token rotated
        if (tok !== p.token) {
          const updated = { ...p, token: tok, refreshToken: ref } as UserProfile;
          setProfile(updated);
          saveProfile(updated);
          syncAuthToGoConfig(tok, p.email, ref);
        }
        setSessionExpired(false);
        return tok;
      }

      // No live session — try explicit refresh with stored refresh token
      if (p.refreshToken) {
        const { data: r } = await supabase.auth.refreshSession({ refresh_token: p.refreshToken });
        if (r.session?.access_token) {
          const tok = r.session.access_token;
          const ref = r.session.refresh_token ?? p.refreshToken;
          const updated = { ...p, token: tok, refreshToken: ref } as UserProfile;
          setProfile(updated);
          saveProfile(updated);
          syncAuthToGoConfig(tok, p.email, ref);
          setSessionExpired(false);
          return tok;
        }
      }
    } catch {}

    // Both paths failed — session is truly expired
    setSessionExpired(true);
    return null;
  }, []);

  // Listen for Supabase-managed token rotation (happens automatically every
  // ~50 min). Keeps profile state and Go config in sync without any polling.
  useEffect(() => {
    const { data: { subscription } } = supabase.auth.onAuthStateChange((event, session) => {
      const p = profileRef.current;
      if (!p?.email) return;

      if (event === "TOKEN_REFRESHED" && session) {
        const tok = session.access_token;
        const ref = session.refresh_token ?? p.refreshToken ?? "";
        const updated = { ...p, token: tok, refreshToken: ref } as UserProfile;
        setProfile(updated);
        saveProfile(updated);
        syncAuthToGoConfig(tok, p.email, ref);
        setSessionExpired(false);
      } else if (event === "SIGNED_OUT") {
        setSessionExpired(true);
      }
    });
    return () => subscription.unsubscribe();
  }, []);

  // ── Auth callbacks ────────────────────────────────────────────────
  // Shared handler — called from both the local-HTTP-server path and the
  // deep-link fallback so the logic lives in one place.
  const handleAuthPayload = useCallback(async (
    token: string, name: string, email: string, refreshToken = "",
  ) => {
    if (!token) return;
    const current = await loadProfile();
    const p: UserProfile = {
      name:  name  || current?.name  || "User",
      email: email || current?.email || "",
      token,
      refreshToken,
    };
    await saveProfile(p);
    setProfile(p);
    setShowAuthForm(false); // close the in-app sign-in modal if it was open
    setSessionExpired(false);
    await syncAuthToGoConfig(token, p.email, refreshToken);
    if (currentServerUrl) fetchAndCachePackages(currentServerUrl);
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [currentServerUrl]);

  // Primary path: local HTTP callback server (works in dev and production).
  useEffect(() => {
    let unlisten: (() => void) | undefined;
    listen<{ token: string; name: string; email: string; refresh_token?: string }>(
      "auth-callback",
      (event) => {
        const { token, name, email, refresh_token } = event.payload;
        handleAuthPayload(token, name, email, refresh_token ?? "");
      },
    ).then((fn) => { unlisten = fn; });
    return () => unlisten?.();
  }, [handleAuthPayload]);

  // Fallback path: trojan:// deep link (production only — dev ignores this
  // because macOS routes the scheme to the installed .app, not the dev server).
  useEffect(() => {
    let unlisten: (() => void) | undefined;
    listen<string[]>("deep-link-received", async (event) => {
      for (const url of event.payload) {
        const parsed = parseAuthCallback(url);
        if (parsed?.token) {
          handleAuthPayload(parsed.token, parsed.name ?? "", parsed.email ?? "", parsed.refreshToken ?? "");
          return;
        }
      }
    }).then((fn) => { unlisten = fn; });
    return () => unlisten?.();
  }, [handleAuthPayload]);

  // Dismiss all scanning toasts when the user cancels mid-scan.
  useEffect(() => {
    let unlisten: (() => void) | undefined;
    listen("scan-cancelled", () => {
      setToasts((prev) => prev.filter((t) => t.status !== "scanning"));
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
      .then(async ({ url, cachePath }) => {
        await fetchAndCachePackages(url);
        setIsDepScanning(false);
        // Store the server URL so Threat Lab can reach it, and set the
        // report entry so the sidebar item appears.
        setScanPath(path);
        setScanType("sast");
        setReportUrl(url);
        await updateRecentUrl(path, url);
        await updateRecentCachePath(path, cachePath);
      })
      .catch((e) => {
        setDepScanError(friendlyError(String(e)));
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
      // Capture finding counts for the printable certificate
      if (Array.isArray(data.findings)) {
        const f: Finding[] = data.findings;
        const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: f.length };
        for (const finding of f) {
          const sev = (finding.severity ?? (finding as Record<string, string>)["Severity"] ?? "info").toLowerCase();
          if (sev in counts) (counts as Record<string, number>)[sev]++;
        }
        setScanSummary({ ...counts, scannedAt: new Date().toISOString() });
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

      const token = await getFreshToken();
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
          user_familiarity: profile?.familiarity ?? 1,
          about_you: profile?.aboutYou ?? "",
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
      setLabError(friendlyError(String(e)));
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
        // Auto-navigate: open the report in the sidebar instead of waiting
        // for the user to click the toast button.
        openReport(url, path, "sast");
      })
      .catch((e) => { if (!String(e).includes("__cancelled__")) updateToastError(id, friendlyError(String(e))); });
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
        // Auto-navigate to report view.
        openReport(rUrl, url, "dast");
      })
      .catch((e) => { if (!String(e).includes("__cancelled__")) updateToastError(id, friendlyError(String(e))); });
  }

  function openReport(url: string, path: string, type: ScanType): void {
    setScanPath(path);
    setScanType(type);
    setReportUrl(url);
    setView("report");
  }

  function openRecent(r: RecentProject): void {
    if (r.cachePath && staleCaches.has(r.path)) {
      // Cache file was deleted — re-run the scan instead of trying to serve it
      r.type === "sast" ? triggerSast(r.path) : triggerDast(r.path);
      return;
    }
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
        .catch((e) => { if (!String(e).includes("__cancelled__")) updateToastError(id, friendlyError(String(e))); });
    } else if (!isScanning) {
      r.type === "sast" ? triggerSast(r.path) : triggerDast(r.path);
    }
    // If isScanning and no cache path, do nothing — scan is already running
  }

  async function deleteRecent(path: string) {
    const updated = await deleteRecentEntry(path);
    setRecent(updated);
    // If the deleted project is what's loaded in the report view, clear it.
    if (scanPath === path) {
      setReportUrl("");
      setScanPath("");
      setView("overview");
    }
  }

  async function clearAllRecent() {
    try {
      const s = await getStore();
      await s.set(STORE_KEY, []);
      await s.save();
    } catch {}
    setRecent([]);
    setReportUrl("");
    setScanPath("");
    if (view === "report") setView("overview");
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


  async function handlePickFolder() {
    const selected = await invoke<string | null>("pick_folder");
    if (selected) triggerSast(selected);
  }

  // ── Gate renders ─────────────────────────────────────────────────────
  if (!profileLoaded) return null;

  if (!profile) return (
    <Onboarding
      onDone={async (p) => {
        setProfile(p);
        // Sync auth to ~/.trojan/config.json immediately so the Go sidecar
        // and the embedded report UI recognise the session on the first scan.
        if (p.token && p.email) {
          await syncAuthToGoConfig(p.token, p.email, p.refreshToken ?? "");
        }
      }}
    />
  );

  // ── Terminal resize handler ───────────────────────────────────────────
  function handleTerminalResizeStart(e: React.MouseEvent) {
    e.preventDefault();
    const startY = e.clientY;
    const startH = terminalHeight;
    const onMove = (ev: MouseEvent) => {
      const delta = startY - ev.clientY;
      setTerminalHeight(Math.max(120, Math.min(window.innerHeight * 0.65, startH + delta)));
    };
    const onUp = () => {
      document.removeEventListener("mousemove", onMove);
      document.removeEventListener("mouseup", onUp);
    };
    document.addEventListener("mousemove", onMove);
    document.addEventListener("mouseup", onUp);
  }

  // ── Main layout ───────────────────────────────────────────────────────
  return (
    <div className="app-layout">

      {/* Sidebar */}
      <aside className="sidebar">
        {/* Logo + wordmark + version */}
        <div className="sidebar-logo-wrap">
          <img src="/logo.png" alt="Trojan" className="sidebar-logo" />
          <span className="sidebar-wordmark">TROJAN</span>
          <span className="sidebar-version">v0.1</span>
        </div>

        <nav className="sidebar-nav">
          {NAV.map(({ view: v, label, icon, pro }) => (
            <button
              key={v}
              className={`sidebar-nav-item ${view === v ? "active" : ""}`}
              onClick={() => setView(v)}
            >
              <span className="nav-icon">{icon}</span>
              <span style={{ flex: 1 }}>{label}</span>
              {pro && (
                <span style={{ font: "600 9px Inter,sans-serif", letterSpacing: "1px", color: "#a78bfa", border: "1px solid rgba(167,139,250,0.4)", padding: "2px 5px" }}>PRO</span>
              )}
            </button>
          ))}

          {/* Dynamic report item — appears once a scan result is available */}
          {reportUrl && (
            <>
              <div className="sidebar-nav-divider" />
              <div className="sidebar-scan-label">CURRENT SCAN</div>
              <button
                className={`sidebar-nav-item sidebar-nav-report ${view === "report" ? "active" : ""}`}
                onClick={() => setView("report")}
              >
                <span className="nav-icon">
                  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
                    <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8l-6-6z M14 2v6h6 M16 13H8 M16 17H8"/>
                  </svg>
                </span>
                <span className="sidebar-report-name">{scanPath.split("/").pop() || "Report"}</span>
                <span className="report-live-dot" />
              </button>
            </>
          )}
        </nav>

        {/* Terminal toggle — pinned above user section like VS Code's panel button */}
        <div className="sidebar-bottom-actions">
          <button
            className={`sidebar-terminal-btn${terminalOpen ? " active" : ""}`}
            onClick={() => setTerminalOpen(o => !o)}
            title={terminalOpen ? "Hide terminal" : "Show terminal"}
          >
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
              <polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/>
            </svg>
            <span>Terminal</span>
          </button>
        </div>

        <div className="sidebar-user">
          <div className="sidebar-avatar">{initials(profile.name)}</div>
          <div className="sidebar-user-info">
            <span className="sidebar-user-name">
              {profile.name}
              {profile.token && <span className="auth-badge">Synced</span>}
            </span>
            {profile.email
              ? <span className="sidebar-user-email">{profile.email}</span>
              : <button className="sidebar-signin-btn" onClick={() => setShowAuthForm(true)}>Sign in →</button>
            }
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
      <div className="app-content" style={{ display: "flex", flexDirection: "column" }}>

        {/* Topbar */}
        <header className="topbar">
          {view === "report" ? (
            <>
              <span className="topbar-title">{scanPath.split("/").pop() || "Scan Report"}</span>
              {scanPath && (
                <span className="topbar-path">{scanPath}</span>
              )}
              <div className="topbar-right">
                <div className="topbar-report-ready">
                  <span className="status-dot status-dot-ok" />
                  REPORT READY
                </div>
                <button
                  className="rescan-btn"
                  onClick={() => scanType === "sast" ? triggerSast(scanPath) : triggerDast(scanPath)}
                >
                  <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"><path d="M3 12a9 9 0 1 0 9-9 9.75 9.75 0 0 0-6.74 2.74L3 8 M3 3v5h5"/></svg>
                  Rescan
                </button>
                <div className="topbar-avatar" title={profile.name}>{initials(profile.name)}</div>
              </div>
            </>
          ) : (
            <>
              <span className="topbar-title">
                {NAV.find((n) => n.view === view)?.label}
              </span>
              <div className="topbar-right">
                <button
                  className={`topbar-terminal-btn${terminalOpen ? " active" : ""}`}
                  onClick={() => setTerminalOpen(o => !o)}
                  title="Toggle terminal"
                >
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
                    <polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/>
                  </svg>
                </button>
                <div className="topbar-avatar" title={profile.name}>{initials(profile.name)}</div>
              </div>
            </>
          )}
        </header>

        {/* Session-expired banner — shown when refresh fails */}
        {sessionExpired && (
          <div className="session-expired-banner">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
            <span>Your session has expired.</span>
            <button className="session-expired-btn" onClick={() => { setShowAuthForm(true); setSessionExpired(false); }}>
              Sign in again →
            </button>
            <button className="session-expired-dismiss" onClick={() => setSessionExpired(false)} title="Dismiss">
              <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
            </button>
          </div>
        )}

        {/* Body — scrollable content above, terminal panel below */}
        <div className="app-body">
        <main className={`content-area${view === "report" ? " content-area--report" : ""}`}>

          {/* ── Overview ── */}
          {view === "overview" && (() => {
            // Posture ring — use Threat Lab data if available
            const ringR   = 63;
            const ringC   = 2 * Math.PI * ringR;
            const tIdx    = threatLabResult?.threat_index ?? null;
            const tGrade  = threatLabResult?.grade ?? null;
            const gradeColors: Record<string, string> = { A:"#16a34a", B:"#65a30d", C:"#d97706", D:"#ea580c", F:"#dc2626" };
            const ringColor  = tGrade ? gradeColors[tGrade] : "#4ade80";
            const ringDash   = tIdx !== null ? `${(ringC * tIdx / 100).toFixed(1)} ${ringC.toFixed(1)}` : `0 ${ringC.toFixed(1)}`;

            // Stats
            const vulnPkgs   = packages.filter(p => p.cve_count > 0).length;
            const now = new Date();
            const dateStr = now.toLocaleDateString("en-US", { weekday:"short", month:"short", day:"numeric", hour:"2-digit", minute:"2-digit" });
            const workspace = profile.email ? profile.email.split("@")[1]?.replace(/\.(com|io|dev|net|org)$/, "") ?? profile.name : profile.name;

            // ── First-run empty state ──────────────────────────────────────
            if (recent.length === 0 && !isScanning) {
              return (
                <div className="first-run-empty">
                  <div className="first-run-logo-wrap">
                    <img src="/logo.png" alt="Trojan" className="first-run-logo" />
                  </div>
                  <h2 className="first-run-title">Secure your codebase</h2>
                  <p className="first-run-desc">
                    Trojan scans your project for vulnerabilities, exposed secrets, and dependency risks — all locally, nothing leaves your machine.
                  </p>
                  <button className="first-run-cta" onClick={handlePickFolder}>
                    Scan a project
                  </button>
                </div>
              );
            }

            return (
              <div className="overview-page">
                <div className="overview-grid-bg" />
                <div className="overview-inner">

                  {/* Header */}
                  <div className="overview-header">
                    <div>
                      <h2 className="overview-greeting">{greet(profile.name)}</h2>
                      <p className="overview-meta">{workspace} workspace · {dateStr}</p>
                    </div>
                    <div className="overview-status-badge">
                      <span className={`status-dot ${isScanning ? "status-dot-warn" : vulnPkgs > 0 ? "status-dot-warn" : "status-dot-ok"}`} />
                      {isScanning ? "SCAN RUNNING" : vulnPkgs > 0 ? `${vulnPkgs} CVEs OPEN` : "SYSTEMS READY"}
                    </div>
                  </div>

                  {/* Row 2: posture ring + 4 stat cards side by side */}
                  <div className="overview-posture-row">
                    {/* Security posture ring card */}
                    <div className="posture-card">
                      <CM />
                      <span className="posture-card-label">SECURITY POSTURE</span>
                      <div className="posture-ring-wrap">
                        <svg className="posture-ring-svg" viewBox="0 0 150 150">
                          <circle className="posture-ring-track" cx="75" cy="75" r={ringR} />
                          <circle
                            className="posture-ring-fill"
                            cx="75" cy="75" r={ringR}
                            stroke={ringColor}
                            strokeDasharray={ringDash}
                          />
                        </svg>
                        {tIdx !== null && <div className="posture-pulse" />}
                        <div className="posture-center">
                          {tGrade ? (
                            <>
                              <span className="posture-grade-text" style={{ color: ringColor }}>{tGrade}</span>
                              <span className="posture-score-text">{tIdx}/100</span>
                            </>
                          ) : (
                            <span className="posture-empty-text">
                              {recent.length > 0 ? "Run\nThreat Lab" : "No scans\nyet"}
                            </span>
                          )}
                        </div>
                      </div>
                      {tGrade && <span className="posture-card-sub">Grade {tGrade} — {tIdx} / 100</span>}
                    </div>

                    {/* 2×2 stat cards */}
                    <div className="stat-grid">
                      <div className="stat-card">
                        <span className="stat-label">SCANS RUN</span>
                        <span className="stat-value">{recent.length || "—"}</span>
                        <span className="stat-sub">all time</span>
                      </div>
                      <div className="stat-card">
                        <span className="stat-label">LAST SCAN</span>
                        <span className="stat-value" style={{ fontSize: recent.length ? 16 : 24, marginTop: recent.length ? 4 : 0 }}>
                          {recent.length ? timeAgo(recent[0].scannedAt) : "—"}
                        </span>
                        <span className="stat-sub">{recent[0]?.name ?? "no history"}</span>
                      </div>
                      <div className="stat-card">
                        <span className="stat-label">PACKAGES</span>
                        <span className="stat-value">{packages.length || "—"}</span>
                        <span className="stat-sub">audited</span>
                      </div>
                      <div className="stat-card">
                        <span className="stat-label">CVEs</span>
                        <span className="stat-value" style={{ color: vulnPkgs > 0 ? "#ea580c" : undefined }}>
                          {packages.length ? vulnPkgs : "—"}
                        </span>
                        <span className="stat-sub">vulnerable pkgs</span>
                      </div>
                    </div>
                  </div>

                  {/* Row 3: station cards */}
                  <div className="station-cards">
                    {/* SAST station */}
                    <div className={`scan-tip-wrap ${isScanning ? "scanning-active" : ""}`}>
                      <div className={`station-card ${isDragOver && !isScanning ? "drag-over" : ""} ${isScanning ? "scan-locked" : ""}`}>
                        <CM />
                        <div className="station-icon-wrap" style={{ color: "#2563eb" }}>
                          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
                            <polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/>
                          </svg>
                        </div>
                        <div>
                          <div className="station-code">STATION 01 — STATIC</div>
                          <div className="station-title">Static Analysis</div>
                        </div>
                        <div className="station-desc">
                          Five scanners over a local codebase: code patterns, CVEs, secrets, IaC policy, SBOM.
                        </div>
                        <div className="station-tech">semgrep · trivy · gitleaks · checkov · syft</div>
                        <div className="station-footer">
                          <button className="station-btn" onClick={handlePickFolder} disabled={isScanning}>
                            {isScanning ? "Scanning…" : "New SAST scan"}
                          </button>
                          <span className="station-last">
                            {recent.filter(r => r.type === "sast")[0]
                              ? `last run ${timeAgo(recent.filter(r => r.type === "sast")[0].scannedAt)}`
                              : "never run"}
                          </span>
                        </div>
                      </div>
                    </div>

                    {/* DAST station */}
                    <div className={`scan-tip-wrap ${isScanning ? "scanning-active" : ""}`}>
                      <div className={`station-card ${isScanning ? "scan-locked" : ""}`} style={{ borderColor: "#7c3aed20" }}>
                        <CM />
                        <div className="station-icon-wrap" style={{ color: "#7c3aed" }}>
                          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
                            <circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/>
                            <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/>
                          </svg>
                        </div>
                        <div>
                          <div className="station-code">STATION 02 — DYNAMIC</div>
                          <div className="station-title">Dynamic Analysis</div>
                        </div>
                        <div className="station-desc">
                          Probe a live server: 6,618 Nuclei templates, CORS, headers, endpoint discovery.
                        </div>
                        <div className="station-tech">nuclei · cors · headers · endpoints</div>
                        <div className="station-footer">
                          <button className="station-btn" onClick={() => setView("dast")} disabled={isScanning}>
                            New DAST scan
                          </button>
                          <span className="station-last">
                            {recent.filter(r => r.type === "dast")[0]
                              ? `last run ${timeAgo(recent.filter(r => r.type === "dast")[0].scannedAt)}`
                              : "never run"}
                          </span>
                        </div>
                      </div>
                    </div>
                  </div>

                  {/* Row 4: recent activity */}
                  {recent.length > 0 && (
                    <div className="activity-section">
                      <div className="activity-header">
                        RECENT ACTIVITY
                        <button className="activity-view-all" onClick={() => setView("history")}>View all →</button>
                      </div>
                      {recent.slice(0, 5).map((r) => (
                        <div key={r.path} className="activity-row" onClick={() => openRecent(r)}>
                          <span className={`activity-dot ${r.type === "sast" ? "activity-dot-ok" : "activity-dot-dast"}`} />
                          <span className="activity-time">{timeAgo(r.scannedAt)}</span>
                          <span className="activity-name">{r.name}</span>
                          <span className={`activity-badge ${r.type === "sast" ? "activity-badge-sast" : "activity-badge-dast"}`}>
                            {(r.type ?? "sast").toUpperCase()}
                          </span>
                          <span className="activity-cta">{r.cachePath && !staleCaches.has(r.path) ? "View →" : "Scan →"}</span>
                          <button
                            className="recent-delete-btn"
                            style={{ position: "static", transform: "none" }}
                            onClick={(e) => { e.stopPropagation(); deleteRecent(r.path); }}
                            title="Delete"
                          >
                            <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
                          </button>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            );
          })()}

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
                <CM />
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
                <p className="scanner-grid-label">SCANNERS — 5 INSTALLED</p>
                <div className="scanner-grid">
                  {[
                    { name: "Semgrep",  desc: "Pattern-based code analysis across 30+ languages.", icon: <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#2563eb" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"><path d="M10 4a6 6 0 1 0 0 12 6 6 0 0 0 0-12 M21 21l-6.65-6.65"/></svg> },
                    { name: "Trivy",    desc: "Known CVEs and misconfigurations in dependencies and images.", icon: <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#2563eb" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"><path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z"/></svg> },
                    { name: "Gitleaks", desc: "Hard-coded secrets, tokens and credentials in code and git history.", icon: <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#2563eb" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"><path d="M12.4 2.7a2.5 2.5 0 0 1 3.4 0l5.5 5.5a2.5 2.5 0 0 1 0 3.4l-3.7 3.7a2.5 2.5 0 0 1-3.4 0L8.7 9.8a2.5 2.5 0 0 1 0-3.4z M14 7l3 3 M9.4 10.6 2 18v4h4l7.4-7.4"/></svg> },
                    { name: "Checkov",  desc: "IaC policy checks — Terraform, CloudFormation, Kubernetes.", icon: <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#2563eb" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"><path d="M12 2 2 7l10 5 10-5-10-5 M2 17l10 5 10-5 M2 12l10 5 10-5"/></svg> },
                    { name: "Syft",     desc: "SBOM generation and license inventory for every artifact.", icon: <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#2563eb" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"><path d="M21 8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16Z M3.3 7l8.7 5 8.7-5 M12 22V12"/></svg> },
                  ].map((f) => (
                    <div key={f.name} className="scanner-chip">
                      <div className="scanner-chip-head">
                        {f.icon}
                        <span className="chip-name" style={{ flex: 1 }}>{f.name}</span>
                        <span className="scanner-ready-dot" />
                        <span className="scanner-ready-label">READY</span>
                      </div>
                      <p className="chip-desc">{f.desc}</p>
                    </div>
                  ))}
                  {/* Last run info cell */}
                  <div className="scanner-last-run">
                    <span className="scanner-last-label">LAST STATIC RUN</span>
                    {recent.filter(r => r.type === "sast")[0] ? (
                      <>
                        <span className="scanner-last-name">{recent.filter(r => r.type === "sast")[0].name} · {timeAgo(recent.filter(r => r.type === "sast")[0].scannedAt)}</span>
                        {recent.filter(r => r.type === "sast")[0].cachePath &&
                         !staleCaches.has(recent.filter(r => r.type === "sast")[0].path) && (
                          <button className="scanner-last-link" onClick={() => openRecent(recent.filter(r => r.type === "sast")[0])}>
                            view report →
                          </button>
                        )}
                      </>
                    ) : (
                      <span className="scanner-last-name">no scans yet</span>
                    )}
                  </div>
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
                <CM />
                <span className="scanner-grid-label">TARGET URL</span>
                <form className="dast-row-form" onSubmit={(e) => { e.preventDefault(); triggerDast(dastUrl); }}>
                  <input
                    className="dast-input dast-input-lg"
                    type="url"
                    placeholder="https://staging.example.com"
                    value={dastUrl}
                    onChange={(e) => setDastUrl(e.target.value)}
                    disabled={isScanning}
                    autoFocus
                    style={{ fontFamily: "'Fira Code', monospace" }}
                  />
                  <button type="submit" className="station-btn" disabled={isScanning || !dastUrl.trim()} style={{ whiteSpace: "nowrap", padding: "0 20px" }}>
                    {isScanning ? "Scan in progress…" : "Start Dynamic Scan"}
                  </button>
                </form>
                <div className="dast-warning">
                  <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="#d97706" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
                    <path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3 M12 9v4 M12 17h.01"/>
                  </svg>
                  Only scan systems you own or are authorized to test.
                </div>
              </div>
              </div>{/* /scan-tip-wrap */}

              <div>
                <p className="scanner-grid-label">CHECKS</p>
                <div className="feature-grid">
                  {([
                    {
                      name: "Nuclei", extra: "6,618 templates", pro: false,
                      desc: "Curated vulnerability templates — CVE probes, exposures, takeovers.",
                      icon: <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="#7c3aed" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"><path d="M4 14a1 1 0 0 1-.78-1.63l9.9-10.2a.5.5 0 0 1 .86.46l-1.92 6.02A1 1 0 0 0 13 10h7a1 1 0 0 1 .78 1.63l-9.9 10.2a.5.5 0 0 1-.86-.46l1.92-6.02A1 1 0 0 0 11 14z"/></svg>,
                    },
                    {
                      name: "CORS", extra: undefined, pro: false,
                      desc: "Cross-origin policy misconfigurations and wildcard origins.",
                      icon: <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="#7c3aed" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"><path d="M12 2a10 10 0 1 0 0 20 10 10 0 0 0 0-20 M2 12h20"/></svg>,
                    },
                    {
                      name: "Security headers", extra: undefined, pro: false,
                      desc: "CSP, HSTS, frame and referrer policies graded per response.",
                      icon: <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="#7c3aed" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"><path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z M9 12l2 2 4-4"/></svg>,
                    },
                    {
                      name: "Endpoint discovery", extra: undefined, pro: false,
                      desc: "Crawl plus common-path probing to map the live surface.",
                      icon: <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="#7c3aed" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"><path d="M10 4a6 6 0 1 0 0 12 6 6 0 0 0 0-12 M21 21l-6.65-6.65"/></svg>,
                    },
                    {
                      name: "AI patterns", extra: undefined, pro: true,
                      desc: "Model-driven probes for logic flaws template libraries miss.",
                      icon: <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="#7c3aed" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"><path d="M9.94 3.94 12 2l2.06 1.94L16 2l1 4 4 1-1.94 2.06L21 12l-1.94 2.06L21 16l-4 1-1 4-2.06-1.94L12 22l-2.06-1.94L8 22l-1-4-4-1 1.94-2.06L3 12l1.94-2.06L3 8l4-1 1-4z"/></svg>,
                    },
                  ] as { name: string; extra?: string; pro: boolean; desc: string; icon: React.ReactNode }[]).map((f) => (
                    <div key={f.name} className={`feature-chip ${f.pro ? "chip-pro" : ""}`}>
                      <div className="chip-head">
                        {f.icon}
                        <span className="chip-name">{f.name}</span>
                        {f.extra && <span className="chip-extra">{f.extra}</span>}
                        {f.pro && <span style={{ font: "600 9px Inter,sans-serif", letterSpacing: "1px", color: "#a78bfa", border: "1px solid rgba(167,139,250,0.4)", padding: "2px 5px" }}>PRO</span>}
                      </div>
                      <span className="chip-desc">{f.desc}</span>
                    </div>
                  ))}
                </div>
              </div>

              {recent.filter(r => r.type === "dast").length > 0 && (
                <div>
                  <p className="scanner-grid-label">RECENT TARGETS</p>
                  <div className="dast-recent-list">
                    {recent.filter(r => r.type === "dast").slice(0, 3).map(r => (
                      <div key={r.path} className="dast-recent-row" onClick={() => openRecent(r)}>
                        <span className="dast-recent-url">{r.path}</span>
                        <span className="dast-recent-time">{timeAgo(r.scannedAt)}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* ── History ── */}
          {view === "history" && (
            <div className="content-inner">
              <div style={{ display: "flex", alignItems: "flex-end", justifyContent: "space-between" }}>
                <div className="view-header">
                  <h2 className="view-title">Scan History</h2>
                  <p className="view-desc">
                    {recent.length > 0
                      ? `${recent.length} scan${recent.length !== 1 ? "s" : ""} — cached results re-open instantly.`
                      : "No scans yet."}
                  </p>
                </div>
                <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
                  {recent.length > 0 && (
                    <button className="history-clear-all-btn" onClick={clearAllRecent}>
                      Clear all
                    </button>
                  )}
                  <div className="history-filter-tabs">
                    {(["all", "sast", "dast"] as const).map(f => (
                      <button
                        key={f}
                        className={`history-filter-tab ${historyFilter === f ? "active" : ""}`}
                        onClick={() => setHistoryFilter(f)}
                      >
                        {f.toUpperCase()}
                      </button>
                    ))}
                  </div>
                </div>
              </div>

              {(() => {
                const filteredRecent = historyFilter === "all" ? recent : recent.filter(r => r.type === historyFilter);
                return filteredRecent.length === 0 ? (
                  <div className="empty-state">
                    <p>Run your first scan from Overview or Static / Dynamic Analysis.</p>
                  </div>
                ) : (
                  <ul className="history-list">
                    {filteredRecent.map((r) => {
                      const isStale = r.cachePath ? staleCaches.has(r.path) : false;
                      return (
                        <li key={r.path} className={`history-item-wrap${isStale ? " history-item-stale" : ""}`}>
                          <button className="history-item" onClick={() => openRecent(r)} title={isStale ? "Cache removed — click to re-scan" : undefined}>
                            <span className={`history-type-badge ${r.type === "sast" ? "activity-badge-sast" : "activity-badge-dast"}`}>
                              {(r.type ?? "sast").toUpperCase()}
                            </span>
                            <span className="recent-left" style={{ flex: 1 }}>
                              <div style={{ display: "flex", flexDirection: "column", gap: 2, minWidth: 0 }}>
                                <span className="recent-name">{r.name}</span>
                                <span className="recent-path">{r.path}</span>
                              </div>
                            </span>
                            {isStale
                              ? <span className="history-status-badge history-status-stale">CACHE REMOVED</span>
                              : r.cachePath
                              ? <span className="history-status-badge history-status-cached">CACHED</span>
                              : <span style={{ width: 60 }} />}
                            <span className="recent-time" style={{ width: 80, textAlign: "right" }}>{timeAgo(r.scannedAt)}</span>
                          </button>
                          <button
                            className="recent-delete-btn history-delete-btn"
                            onClick={() => deleteRecent(r.path)}
                            title="Delete this scan"
                          >
                            <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
                          </button>
                        </li>
                      );
                    })}
                  </ul>
                );
              })()}
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
                <CM />
                {isDepScanning ? (
                  <>
                    <span className="dep-spinner" />
                    <div className="dep-drop-text">
                      <p className="dep-drop-title">Scanning dependencies…</p>
                      <p className="dep-drop-sub">Running Trivy on your project</p>
                    </div>
                  </>
                ) : depDragOver ? (
                  <p className="dep-drop-title">Release to scan dependencies</p>
                ) : (
                  <>
                    <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" className="dep-drop-icon">
                      <path d="M21 8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16Z M3.3 7l8.7 5 8.7-5 M12 22V12"/>
                    </svg>
                    <div className="dep-drop-text">
                      <p className="dep-drop-title">Drop a project folder to audit its lockfiles</p>
                      <p className="dep-drop-sub">package-lock.json · go.sum · poetry.lock · Cargo.lock</p>
                    </div>
                    <button
                      className="dep-drop-browse"
                      onClick={(e) => { e.stopPropagation(); invoke<string | null>("pick_folder").then(p => p && triggerDeps(p)); }}
                    >
                      Browse…
                    </button>
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
                        { label: "TOTAL",          value: packages.length },
                        { label: "VULNERABLE",     value: packages.filter(p => p.cve_count > 0).length },
                        { label: "DIRECT",         value: packages.filter(p => p.direct).length },
                        { label: "CRITICAL + HIGH", value: packages.filter(p => p.highest_severity === "critical" || p.highest_severity === "high").length },
                      ].map((s) => (
                        <div key={s.label} className="dep-stat">
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
            const gradeColors: Record<string, string> = { A:"#16a34a", B:"#65a30d", C:"#d97706", D:"#ea580c", F:"#dc2626" };
            const gradeColorVal = r ? (gradeColors[r.grade] ?? "#4ade80") : "#4ade80";
            // Ring: r=50, circumference=314.16
            const ringC = 2 * Math.PI * 50;
            const ringDash = r ? `${(ringC * r.threat_index / 100).toFixed(1)} ${ringC.toFixed(1)}` : `0 ${ringC.toFixed(1)}`;

            return (
              <div className="lab-content lab-print-area">

                {/* ── Header row ── */}
                <div className="lab-header-row">
                  <div>
                    <div className="lab-title-row">
                      <span className="lab-title-text">Threat Lab</span>
                      <span className="lab-pro-tag">PRO</span>
                    </div>
                    <p className="lab-subtitle">
                      {r && scanPath
                        ? `AI attack-surface analysis of ${scanPath.split("/").pop()} — SAST and dependency data combined.`
                        : "AI-powered attack surface analysis combining SAST + dependency data."}
                    </p>
                  </div>
                  <div className="lab-header-actions">
                    {r && (
                      <>
                        <button className="lab-export-btn" onClick={exportLabTxt}>
                          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
                          Export TXT
                        </button>
                        <button className="lab-export-btn" onClick={exportLabPdf}>
                          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>
                          Export PDF
                        </button>
                      </>
                    )}
                    {hasData && isPro && (
                      <button
                        className={`lab-run-primary ${isLabRunning ? "lab-btn-loading" : ""}`}
                        onClick={runThreatLab}
                        disabled={isLabRunning}
                      >
                        {isLabRunning ? <><span className="lab-spinner" /> Analysing…</> : r ? "Re-run Analysis" : "Run Threat Lab"}
                      </button>
                    )}
                  </div>
                </div>

                {/* ── State messages ── */}
                {!hasData && (
                  <div className="lab-state-card">
                    <p className="lab-no-data">Run a scan first from Static Analysis or Dependencies — then come back here.</p>
                  </div>
                )}
                {hasData && !isPro && (
                  <div className="lab-state-card lab-pro-gate">
                    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
                    Threat Lab requires a Pro subscription.
                    <button className="lab-upgrade-btn" onClick={() => setShowAuthForm(true)}>Upgrade →</button>
                  </div>
                )}
                {hasData && isPro && !r && !isLabRunning && (
                  <div className="lab-state-card">
                    <p className="lab-no-data">Analyzes your last scan — manual trigger only, results cached 6 hours.</p>
                  </div>
                )}
                {labError && <p className="lab-error">{labError}</p>}

                {/* ── Results ── */}
                {r && (
                  <>
                    {/* Score row — 3 cards */}
                    <div className="lab-score-row-v2">

                      {/* Threat Index */}
                      <div className="lab-index-card">
                        <div className="corner-marks">
                          <i className="corner-mark cm-tl">+</i><i className="corner-mark cm-tr">+</i>
                          <i className="corner-mark cm-bl">+</i><i className="corner-mark cm-br">+</i>
                        </div>
                        <div className="lab-index-card-label">THREAT INDEX</div>
                        <div className="lab-index-ring-wrap">
                          <svg width="120" height="120" viewBox="0 0 120 120" style={{ transform: "rotate(-90deg)" }}>
                            <circle cx="60" cy="60" r="50" fill="none" stroke="oklch(0.92 0 0)" strokeWidth="8" />
                            <circle cx="60" cy="60" r="50" fill="none" stroke={gradeColorVal} strokeWidth="8" strokeDasharray={ringDash} />
                          </svg>
                          <div className="lab-ring-center">
                            <span className="lab-index-num">{r.threat_index}</span>
                            <span className="lab-ring-denom">/100</span>
                          </div>
                        </div>
                        <div className="lab-index-sub2">higher = more exposed</div>
                      </div>

                      {/* Grade */}
                      <div className="lab-grade-card">
                        <div className="lab-index-card-label">GRADE</div>
                        <div className="lab-grade-box">
                          <span className="lab-grade-letter" style={{ borderColor: gradeColorVal, color: gradeColorVal }}>
                            {r.grade}
                          </span>
                        </div>
                        <div className="lab-index-sub2">
                          {r.grade === "A" ? "excellent" : r.grade === "B" ? "good" : r.grade === "C" ? "fair" : r.grade === "D" ? "needs attention" : "critical"}
                        </div>
                      </div>

                      {/* Verdict */}
                      <div className="lab-verdict-card">
                        <div className="lab-index-card-label">VERDICT</div>
                        <p className="lab-verdict-text">{r.verdict}</p>
                      </div>
                    </div>

                    {/* Two-column body */}
                    <div className="lab-body-cols">

                      {/* Left: Key risks + Attack vectors */}
                      <div className="lab-body-left">
                        <div className="lab-card">
                          <div className="lab-card-label">KEY RISKS</div>
                          {r.key_risks.map((risk, i) => (
                            <div key={i} className="lab-risk-item">
                              <span className="lab-risk-sq" style={{
                                background: i <= 1 ? "#dc2626" : i === 2 ? "#ea580c" : "#d97706"
                              }} />
                              {risk}
                            </div>
                          ))}
                        </div>

                        <div className="lab-card">
                          <div className="lab-card-label">ATTACK VECTORS</div>
                          {r.attack_vectors.map((v, i) => (
                            <div key={i} className="lab-vector-v2">
                              <div className="lab-vector-head">
                                <span className={`dep-sev-badge dep-sev-${v.severity}`}>{v.severity}</span>
                                <span className="lab-vector-title">{v.title}</span>
                                <span className="lab-vector-exploit">exploitability: {v.exploitability.toUpperCase()}</span>
                              </div>
                              <p className="lab-vector-desc">{v.description}</p>
                              {v.findings_involved.length > 0 && (
                                <p className="lab-vector-findings">findings: {v.findings_involved.join(", ")}</p>
                              )}
                            </div>
                          ))}
                        </div>
                      </div>

                      {/* Right: Priority fixes + Compliance */}
                      <div className="lab-body-right">
                        <div className="lab-card" style={{ position: "relative" }}>
                          <div className="corner-marks">
                            <i className="corner-mark cm-tl">+</i><i className="corner-mark cm-tr">+</i>
                            <i className="corner-mark cm-bl">+</i><i className="corner-mark cm-br">+</i>
                          </div>
                          <div className="lab-card-label">PRIORITY FIXES</div>
                          {r.priority_fixes.map((f) => (
                            <div key={f.rank} className="lab-fix-v2">
                              <span className="lab-fix-rank">{f.rank}</span>
                              <div className="lab-fix-body">
                                <div className="lab-fix-head">
                                  <span className={`lab-fix-type lab-fix-type-${f.type}`}>{f.type}</span>
                                  <span className="lab-fix-title">{f.title}</span>
                                </div>
                                {f.command && (
                                  <div className="lab-fix-cmd-wrap">
                                    <code className="lab-fix-cmd">{f.command}</code>
                                    <button className="lab-copy-btn" onClick={() => navigator.clipboard.writeText(f.command!)} title="Copy">
                                      <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="rgba(255,255,255,0.5)" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
                                        <path d="M8 8h12v12H8z M16 8V6a2 2 0 0 0-2-2H6a2 2 0 0 0-2 2v8a2 2 0 0 0 2 2h2"/>
                                      </svg>
                                    </button>
                                  </div>
                                )}
                                {f.file && (
                                  <p className="lab-fix-file-path">{f.file}{f.line ? `:${f.line}` : ""}</p>
                                )}
                              </div>
                            </div>
                          ))}
                        </div>

                        <div className="lab-card">
                          <div className="lab-card-label">COMPLIANCE NOTES</div>
                          <p className="lab-compliance">{r.compliance_summary}</p>
                        </div>
                      </div>

                    </div>
                  </>
                )}
              </div>
            );
          })()}

          {/* ── Profile ── */}
          {view === "profile" && (() => {
            const fams = [
              { name: "Non-technical founder", desc: "Plain language, no jargon — what each risk means for your business and customers." },
              { name: "Junior developer",      desc: "Balanced detail, with security concepts explained as they come up." },
              { name: "Experienced developer", desc: "Full technical detail, security jargon, code-level." },
            ];
            const fam = profile.familiarity ?? 1;
            const famPct = ["0%", "50%", "100%"][fam];

            function updateProfile(patch: Partial<UserProfile>) {
              const updated = { ...profile, ...patch } as UserProfile;
              setProfile(updated);
              saveProfile(updated);
            }

            function handleAvatarFile(file: File) {
              if (!file.type.startsWith("image/")) return;
              const reader = new FileReader();
              reader.onload = e => {
                const dataUrl = e.target?.result as string;
                if (dataUrl) updateProfile({ avatarDataUrl: dataUrl });
              };
              reader.readAsDataURL(file);
            }

            const CM = () => (
              <>
                <i className="corner-mark cm-tl">+</i>
                <i className="corner-mark cm-tr">+</i>
                <i className="corner-mark cm-bl">+</i>
                <i className="corner-mark cm-br">+</i>
              </>
            );

            return (
              <div className="profile-page">
                <div className="profile-inner">

                  {/* ── Header: avatar + name + subtitle ── */}
                  <div className="profile-header-row">

                    {/* Drag-drop avatar */}
                    <label
                      className="profile-avatar-wrap"
                      onDragOver={e => { e.preventDefault(); e.currentTarget.classList.add("drag-over"); }}
                      onDragLeave={e => e.currentTarget.classList.remove("drag-over")}
                      onDrop={e => {
                        e.preventDefault();
                        e.currentTarget.classList.remove("drag-over");
                        const file = e.dataTransfer.files[0];
                        if (file) handleAvatarFile(file);
                      }}
                      title="Click or drag an image to set your photo"
                    >
                      {profile.avatarDataUrl
                        ? <img src={profile.avatarDataUrl} alt="avatar" className="profile-avatar-img" />
                        : <span className="profile-avatar-initials">{initials(profile.name)}</span>
                      }
                      <span className="profile-avatar-overlay">
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                          <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/>
                        </svg>
                      </span>
                      <input type="file" accept="image/*" className="profile-avatar-input" onChange={e => { const f = e.target.files?.[0]; if (f) handleAvatarFile(f); }} />
                    </label>

                    <div className="profile-header-text">
                      <div className="profile-name-display">{profile.name || "Your name"}</div>
                      <div className="profile-subtitle">Trojan uses your details to understand your background and tailor all reports, explanations, and AI analysis accordingly.</div>
                    </div>
                  </div>

                  {/* ── Identity card ── */}
                  <div className="profile-card">
                    <CM />
                    <label className="profile-field">
                      <span className="profile-mono-label">DISPLAY NAME</span>
                      <input
                        className="profile-input"
                        type="text"
                        value={profile.name}
                        placeholder="Your name"
                        onChange={e => updateProfile({ name: e.target.value })}
                      />
                    </label>
                    {profile.email && (
                      <label className="profile-field">
                        <span className="profile-mono-label">EMAIL</span>
                        <input className="profile-input profile-input--readonly" type="email" value={profile.email} readOnly />
                      </label>
                    )}
                  </div>

                  {/* ── Your context ── */}
                  <div className="profile-section-group">
                    <span className="profile-mono-label">YOUR CONTEXT</span>
                    <div className="profile-card">
                      <CM />
                      <span className="profile-field-title">Tell us a bit more about you</span>
                      <textarea
                        className="profile-textarea profile-textarea--tall"
                        value={profile.aboutYou ?? ""}
                        placeholder={"Describe your priorities, risk tolerance, and the kind of summaries you find useful. For example:\n\n• I work on products in a regulated industry (healthcare), so compliance and data privacy are top concerns.\n• I prefer short, prioritized action lists — not exhaustive reports.\n• I care most about risks that affect end users or could cause a breach.\n• I'm comfortable with technical terms but need context on security-specific concepts."}
                        onChange={e => updateProfile({ aboutYou: e.target.value })}
                      />
                      <span className="profile-hint">This context is used across all Trojan AI features — findings explanations, Threat Lab reports, remediation advice, and more.</span>
                    </div>
                  </div>

                  {/* ── Security familiarity ── */}
                  <div className="profile-section-group">
                    <span className="profile-mono-label">SECURITY FAMILIARITY</span>
                    <div className="profile-card">
                      <CM />
                      <span className="profile-fam-intro">Sets the technical depth of all explanations, combined with your context above.</span>

                      <div className="profile-fam-slider-wrap">
                        <div className="profile-fam-track-wrap">
                          <div className="profile-fam-track-bg" />
                          <div className="profile-fam-track-fill" style={{ width: famPct }} />
                          {[0, 1, 2].map(i => (
                            <div
                              key={i}
                              className="profile-fam-dot-hit"
                              style={{ left: i === 0 ? "0%" : i === 1 ? "50%" : "100%" }}
                              onClick={() => updateProfile({ familiarity: i })}
                            >
                              <span
                                className="profile-fam-dot"
                                style={{
                                  width:      i === fam ? 16 : 12,
                                  height:     i === fam ? 16 : 12,
                                  background: i <= fam ? "#7c3aed" : "#c9c9cf",
                                  boxShadow:  i === fam ? "0 0 0 4px rgba(124,58,237,0.16)" : "none",
                                }}
                              />
                            </div>
                          ))}
                        </div>
                        <div className="profile-fam-labels">
                          {["Non-technical founder", "Junior developer", "Experienced developer"].map((lbl, i) => (
                            <span
                              key={i}
                              className="profile-fam-label"
                              style={{
                                color:      i === fam ? "#6d28d9" : "oklch(0.5 0 0)",
                                fontWeight: i === fam ? 600 : 400,
                                textAlign:  i === 0 ? "left" : i === 1 ? "center" : "right",
                                cursor: "pointer",
                              }}
                              onClick={() => updateProfile({ familiarity: i })}
                            >
                              {lbl}
                            </span>
                          ))}
                        </div>
                      </div>

                      <div className="profile-fam-badge">
                        <span className="profile-fam-badge-name">{fams[fam].name}</span>
                        <span className="profile-fam-badge-desc">{fams[fam].desc}</span>
                      </div>
                    </div>
                    <span className="profile-autosave-note">Changes are saved automatically.</span>
                  </div>

                </div>
              </div>
            );
          })()}

          {/* ── Scan report iframe ── */}
          {/* Always mounted when reportUrl is set so switching tabs doesn't trigger a reload */}
          {reportUrl && (
            <iframe
              ref={iframeRef}
              className="report-frame-inline"
              style={view !== "report" ? { display: "none" } : undefined}
              src={reportUrl}
              title="Trojan Security Report"
            />
          )}

        </main>

        {/* ── Terminal panel — VS Code-style resizable bottom panel ── */}
        {terminalOpen && (
          <>
            <div className="terminal-resize-handle" onMouseDown={handleTerminalResizeStart} />
            <div className="terminal-panel" style={{ height: terminalHeight }}>
              <div className="terminal-header">
                <div className="terminal-tabs">
                  <span className="terminal-tab-item active">
                    <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" style={{ marginRight: 5 }}>
                      <polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/>
                    </svg>
                    TERMINAL
                  </span>
                </div>
                <div className="terminal-header-actions">
                  <button className="terminal-action-btn" onClick={() => setTerminalOpen(false)} title="Close panel">
                    <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
                  </button>
                </div>
              </div>
              <TerminalPanel
                height={terminalHeight - 32}
                onScan={triggerSast}
                onDast={triggerDast}
                onDeps={triggerDeps}
              />
            </div>
          </>
        )}

        </div>{/* end .app-body */}
      </div>

      {/* ── In-app auth modal ── */}
      {showAuthForm && (
        <div className="auth-overlay" onClick={() => setShowAuthForm(false)}>
          <div className="auth-modal" onClick={(e) => e.stopPropagation()}>
            <CM />
            <img src="/logo.png" alt="Trojan" style={{ width: 40, height: "auto", objectFit: "contain", display: "block" }} />
            <div className="auth-modal-header">
              <h2 className="auth-modal-title">Sign in to Trojan</h2>
              <button className="auth-modal-close" onClick={() => setShowAuthForm(false)} title="Close">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round">
                  <line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/>
                </svg>
              </button>
            </div>
            <AuthForm onAuth={(token, name, email, refreshToken) => handleAuthPayload(token, name, email, refreshToken)} />
          </div>
        </div>
      )}

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
              {t.status === "scanning" && (
                <button
                  className="toast-cancel-btn"
                  onClick={() => invoke("cancel_scan")}
                  title="Cancel scan"
                >
                  Cancel
                </button>
              )}
              {t.status !== "scanning" && (
                <button className="toast-dismiss" onClick={() => dismissToast(t.id)} title="Dismiss">
                  <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
                </button>
              )}
            </div>
          ))}
        </div>
      )}

      {/* PrintCertificate renders via portal directly into document.body */}
      <PrintCertificate
        projectPath={scanPath}
        scanSummary={scanSummary}
        threatLabResult={threatLabResult}
        packages={packages}
      />

    </div>
  );
}
