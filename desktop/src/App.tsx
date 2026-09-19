import { useCallback, useEffect, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { getCurrentWebviewWindow } from "@tauri-apps/api/webviewWindow";
import { openUrl } from "@tauri-apps/plugin-opener";
import { TerminalPanel } from "./TerminalPanel";
import { PrintCertificate } from "./PrintCertificate";
import { PrintComplianceReport } from "./PrintComplianceReport";
import { PrintPenTestReport } from "./PrintPenTestReport";
import type { PentestReport } from "./PrintPenTestReport";
import { AttackMarket, prefetchAttackMarket } from "./AttackMarket";
import type { AttackTemplate } from "./AttackMarket";
import { McpConnect } from "./McpConnect";
import { OrgContextEditor, LocalPrivacyBadge } from "./components/OrgContext";
import { syncDraftToServer } from "./lib/orgContext";
import { gradeColor, licenseRiskColor } from "./lib/reportColors";
import { MARKETING_URL, STORE_KEY, SUPABASE_URL, TERMINAL_KEY, APP_VERSION } from "./constants";
import { supabase, decodeJWT, encodeBody, syncAuthToGoConfig } from "./lib/supabase";
import { completeSignIn, onOnboardingDone } from "./lib/auth";
import { createExternalLinkListener, isIframeOffOrigin, restoreReport } from "./lib/reportBridge";
import {
  getStore,
  loadProfile,
  saveProfile,
  loadRecent,
  saveRecent,
  updateRecentUrl,
  updateRecentCachePath,
  deleteRecentEntry,
} from "./lib/store";
import { friendlyError, timeAgo, parseAuthCallback, greet, initials } from "./lib/format";
import { AuthForm } from "./components/AuthForm";
import { Onboarding } from "./components/Onboarding";
import { CM } from "./components/CornerMarks";
import { FeedbackForm } from "./components/FeedbackForm";
import { TokenBalance, RunCostHint } from "./components/TokenBalance";
import type {
  NavView,
  ScanType,
  PkgInfo,
  PrivacyReport,
  ComplianceLabResult,
  Finding,
  ScanSummary,
  ThreatLabResult,
  AuthStatus,
  RecentProject,
  UserProfile,
  Toast,
} from "./types";
import "./App.css";


// ── Nav icons — exact paths from design file ───────────────────────────
const NAV: { view: NavView; label: string; icon: React.ReactNode; pro?: boolean; section?: string }[] = [
  // ── Security ──
  { view: "overview", label: "Overview", section: "SECURITY",
    icon: <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"><path d="M12 14l4-4 M3.34 19a10 10 0 1 1 17.32 0"/></svg>,
  },
  { view: "sast", label: "Static Analysis",
    icon: <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"><path d="M16 18l6-6-6-6 M8 6l-6 6 6 6"/></svg>,
  },
  { view: "dast", label: "Penetration Testing",
    icon: <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"><path d="M12 2a10 10 0 1 0 0 20 10 10 0 0 0 0-20 M2 12h20 M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10"/></svg>,
  },
  { view: "market", label: "Attack Market",
    icon: <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"><path d="M3 3h2l.4 2M7 13h10l4-8H5.4M7 13L5.4 5M7 13l-2.3 2.3c-.6.6-.2 1.7.7 1.7H17 M9 20a1 1 0 1 0 0-2 1 1 0 0 0 0 2z M16 20a1 1 0 1 0 0-2 1 1 0 0 0 0 2z"/></svg>,
  },
  { view: "dependencies", label: "Dependencies",
    icon: <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"><path d="M21 8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16Z M3.3 7l8.7 5 8.7-5 M12 22V12"/></svg>,
  },
  // ── Compliance & Privacy ──
  { view: "licenses", label: "Licenses", section: "COMPLIANCE",
    icon: <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6"/><path d="M9 15l2 2 4-4"/></svg>,
  },
  { view: "privacy", label: "Privacy",
    icon: <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>,
  },
  // ── General ──
  { view: "history", label: "Scan History", section: "GENERAL",
    icon: <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"><path d="M3 12a9 9 0 1 0 9-9 9.75 9.75 0 0 0-6.74 2.74L3 8 M3 3v5h5 M12 7v5l4 2"/></svg>,
  },
  { view: "autofix", label: "Fix with AI",
    icon: <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"><path d="M12 2L2 7l10 5 10-5-10-5z M2 17l10 5 10-5 M2 12l10 5 10-5"/></svg>,
  },
  { view: "context", label: "Project Context",
    icon: <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M9 12l2 2 4-4"/></svg>,
  },
  { view: "profile", label: "Profile",
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
  // True once the report iframe has navigated outside its own origin (e.g. a
  // stray link the postMessage bridge below didn't catch). Drives the
  // defensive "Back to report" bar.
  const [iframeOffOrigin, setIframeOffOrigin] = useState(false);
  const [isDragOver, setIsDragOver]       = useState(false);
  const [recent, setRecent]               = useState<RecentProject[]>([]);
  const [dastUrl, setDastUrl]             = useState("");
  const [agenticMode, setAgenticMode]     = useState(false);
  const [agTier, setAgTier]               = useState<"passive" | "safe-active" | "aggressive">("passive");
  const [agEnv, setAgEnv]                 = useState<"production" | "staging">("production");
  const [agAck, setAgAck]                 = useState(false);
  const [agGreyBox, setAgGreyBox]         = useState(false);
  const [agFocus, setAgFocus]             = useState<"" | "api" | "web" | "llm">("");
  const [agIdentities, setAgIdentities]   = useState<{ name: string; header: string }[]>([]);
  const [agApiSpec, setAgApiSpec]         = useState("");
  const [agRequireApproval, setAgRequireApproval] = useState(false);
  const [agAllowEndpoints, setAgAllowEndpoints]   = useState("");
  const [agDenyEndpoints, setAgDenyEndpoints]     = useState("");
  const [agLimitToAllowlist, setAgLimitToAllowlist] = useState(false);
  const [agAllowDangerous, setAgAllowDangerous]   = useState(false);
  const [agTemplate, setAgTemplate]               = useState<AttackTemplate | null>(null);
  const [dastFindings, setDastFindings]   = useState<any[]>([]);
  const [pentestReport, setPentestReport] = useState<PentestReport | null>(null);
  const [pentestReportRunning, setPentestReportRunning] = useState(false);
  const [toasts, setToasts]               = useState<Toast[]>([]);
  const [packages, setPackages]           = useState<PkgInfo[]>([]);
  const [privacyReport, setPrivacyReport] = useState<PrivacyReport | null>(null);
  const [complianceLabResult, setComplianceLabResult] = useState<ComplianceLabResult | null>(null);
  const [complianceLabRunning, setComplianceLabRunning] = useState(false);
  const [complianceLabError, setComplianceLabError] = useState<string | null>(null);
  const [pkgExpanded, setPkgExpanded]     = useState<string | null>(null);
  const [advExpanded, setAdvExpanded]     = useState<Set<string>>(new Set());
  const [depPage, setDepPage]             = useState(0);
  const [licPages, setLicPages]           = useState<Record<string, number>>({});
  const [expandedPrivacy, setExpandedPrivacy] = useState<Set<string>>(new Set());
  const [isDepScanning, setIsDepScanning] = useState(false);
  const [depScanError, setDepScanError]   = useState<string | null>(null);
  const [depDragOver, setDepDragOver]     = useState(false);
  const [currentServerUrl, setCurrentServerUrl] = useState<string | null>(null);
  const [authStatus, setAuthStatus]       = useState<AuthStatus | null>(null);
  // Trojan Token balance -- the BILLING unit, not LLM tokens. null = not yet
  // loaded, which renders as "—" rather than 0 (0 would read as "you are out").
  const [tokenBalance, setTokenBalance]   = useState<number | null>(null);
  const [scanSummary, setScanSummary]         = useState<ScanSummary | null>(null);
  const [threatLabResult, setThreatLabResult] = useState<ThreatLabResult | null>(null);
  const [isLabRunning, setIsLabRunning]   = useState(false);
  const [labError, setLabError]           = useState<string | null>(null);
  const [showAuthForm, setShowAuthForm]   = useState(false);
  const [showFeedback, setShowFeedback]   = useState(false);
  const [historyFilter, setHistoryFilter] = useState<"all" | "sast" | "dast">("all");
  const [staleCaches, setStaleCaches]     = useState<Set<string>>(new Set());
  const [terminalOpen, setTerminalOpen]   = useState(true);
  const [terminalHeight, setTerminalHeight] = useState(220);
  const [sessionExpired, setSessionExpired] = useState(false);
  const [mcpStatus, setMcpStatus]         = useState<Record<string, { installed: boolean; configured: boolean }>>({});
  const [mcpSetupBusy, setMcpSetupBusy]   = useState(false);
  const [fixScanIdx, setFixScanIdx]       = useState(0);
  const [fixScanPage, setFixScanPage]     = useState(0);
  const [profileSaved, setProfileSaved]   = useState(true);
  const [profileJustSaved, setProfileJustSaved] = useState(false);
  const savedProfileRef = useRef<{ aboutYou: string; familiarity: number }>({ aboutYou: "", familiarity: 1 });

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

  // Balance rides along on the license endpoint, which the app already polls,
  // rather than adding a second round trip. Failures leave the last known value
  // in place: a transient network error should not make the chip read "0" and
  // tell the user they are out of tokens when they are not.
  const refreshTokenBalance = useCallback(async () => {
    try {
      const token = await getFreshToken();
      if (!token) { setTokenBalance(null); return; }
      const res = await fetch(`${SUPABASE_URL}/functions/v1/license`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (!res.ok) return;
      const data = await res.json();
      if (typeof data.tokenBalance === "number") setTokenBalance(data.tokenBalance);
    } catch {
      // keep the previous value
    }
  }, [getFreshToken]);

  // Single entry point for "we have a valid token, make the whole app know
  // the user is signed in". EVERY sign-in completion path (OAuth deep link,
  // in-app auth modal, onboarding, boot-time session restore) must call this
  // -- authStatus, not profile, is what every gate reads (e.g. the
  // Penetration Testing tab's `authStatus?.loggedIn`). Skipping it anywhere
  // is exactly how the "sign in twice" bug happened.
  const applyAuthFromToken = useCallback((token: string, email: string) => {
    completeSignIn(token, email, { decodeJWT, setAuthStatus, refreshTokenBalance });
  }, [refreshTokenBalance]);

  // Boot: restore profile, recents, terminal prefs and any live session.
  // Placed AFTER getFreshToken/refreshTokenBalance because it depends on them;
  // a dependency declared later in the component body would be in the temporal
  // dead zone when the dep array is evaluated during render.
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
      if (activeProfile) {
        savedProfileRef.current = { aboutYou: activeProfile.aboutYou ?? "", familiarity: activeProfile.familiarity ?? 1 };
      }
      if (activeProfile?.token && activeProfile.email) {
        syncAuthToGoConfig(activeProfile.token, activeProfile.email, activeProfile.refreshToken ?? "");
        // Restore authStatus from the JWT so gates (e.g. Penetration Testing)
        // work before any scan server is running.
        applyAuthFromToken(activeProfile.token, activeProfile.email);
      }
    }
    init();

    // Load MCP editor status on mount
    invoke("check_mcp_status").then((s) => setMcpStatus(s as Record<string, { installed: boolean; configured: boolean }>)).catch(() => {});
  }, [applyAuthFromToken]);

  // Warm the Attack Market catalog in the background once the user is a logged-in
  // Pro, so the first open of the tab is instant (and it never reload-flashes).
  useEffect(() => {
    if (authStatus?.loggedIn) {
      prefetchAttackMarket(async () => (await getFreshToken()) ?? "");
    }
  }, [authStatus?.loggedIn, getFreshToken]);


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
    // Set auth status immediately from the JWT so gates work even before a
    // scan server is running.
    applyAuthFromToken(token, p.email);
    if (currentServerUrl) fetchAndCachePackages(currentServerUrl);
  }, [currentServerUrl, applyAuthFromToken]);

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

  // Bridge for external links clicked inside the report iframe (ui/ and
  // dast-ui/ are standalone-buildable with zero Tauri imports, so they can't
  // call openUrl() themselves -- they postMessage this window instead). A
  // plain <a> with no target would navigate the iframe itself, and
  // target="_blank" silently no-ops because the webview has no new-window
  // handler; this is the fix for both.
  useEffect(() => {
    const listener = createExternalLinkListener(
      () => iframeRef.current?.contentWindow ?? null,
      (url) => { openUrl(url).catch(() => {}); },
    );
    window.addEventListener("message", listener);
    return () => window.removeEventListener("message", listener);
  }, []);

  // A brand-new report load always starts on-origin.
  useEffect(() => { setIframeOffOrigin(false); }, [reportUrl]);

  // Defensive backstop for the bridge above: fires on every real iframe
  // navigation (not on the report's own internal SPA routing, which never
  // triggers a load event). If it ever lands off the report's origin --
  // something the bridge didn't catch -- show the "Back to report" bar.
  function handleReportFrameLoad() {
    const frame = iframeRef.current;
    if (!frame) return;
    setIframeOffOrigin(isIframeOffOrigin(reportUrl, () => frame.contentWindow?.location.href ?? null));
  }

  // Dismiss all scanning toasts when the user cancels mid-scan.
  useEffect(() => {
    let unlisten: (() => void) | undefined;
    listen("scan-cancelled", () => {
      setToasts((prev) => prev.filter((t) => t.status !== "scanning"));
    }).then((fn) => { unlisten = fn; });
    return () => unlisten?.();
  }, []);

  // Balance can also change from outside this window entirely -- a top-up on
  // the web dashboard, a teammate's run on a shared org. Refreshing on every
  // token-spending action in this app (above) keeps it accurate for what we
  // did; this catches everything else without polling while the window sits
  // idle in the background.
  useEffect(() => {
    function onFocus() { void refreshTokenBalance(); }
    window.addEventListener("focus", onFocus);
    return () => window.removeEventListener("focus", onFocus);
  }, [refreshTokenBalance]);

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
    // A finished run has almost certainly moved the balance. Refresh rather
    // than leave a stale number sitting in the sidebar.
    void refreshTokenBalance();
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
    // If the user authored an org context during onboarding and this project
    // doesn't have one yet, write it into the project's .trojan/context.yaml
    // now that a server (which knows the project root) is running. Fire and
    // forget: it never blocks or breaks a scan, and retries on the next one.
    void syncDraftToServer(serverUrl);
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
      if (data.privacy) setPrivacyReport(data.privacy);
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
          const sev = (finding.severity ?? (finding as unknown as Record<string, string>)["Severity"] ?? "info").toLowerCase();
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
      if (!token) throw new Error("Sign in to generate a security report");

      const res = await fetch(`${SUPABASE_URL}/functions/v1/threat-lab`, {
        method: "POST",
        headers: {
          "Authorization": `Bearer ${token}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          encoded: encodeBody({
            project_path: scanData.project_path ?? "",
            findings,
            packages: pkgs,
            user_familiarity: profile?.familiarity ?? 1,
          }),
        }),
      });

      if (res.status === 403) throw new Error("Sign in to generate a security report. Costs 100 tokens.");
      if (res.status === 429) throw new Error("Daily security report limit reached. Try again tomorrow.");
      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error((err as { error?: string }).error ?? `Request failed (${res.status})`);
      }

      const result = await res.json() as ThreatLabResult;
      setThreatLabResult(result);
      // This run just spent tokens (or confirmed a cache hit spent none) --
      // refresh rather than leave the sidebar showing the pre-run balance.
      void refreshTokenBalance();
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
      "TROJAN SECURITY REPORT",
      "======================",
      "",
      `Security Score: ${100 - r.threat_index}/100  |  Grade: ${r.grade}`,
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
    a.download = "trojan-security-report.txt";
    a.click();
    URL.revokeObjectURL(a.href);
  }

  function exportLabPdf() {
    const t = document.title;
    document.title = `Security Assessment - ${scanPath?.split("/").pop() ?? "Report"}`;
    window.print();
    document.title = t;
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

  function triggerAgenticDast(url: string): void {
    if (!url.trim() || isScanning) return;
    const id = crypto.randomUUID();
    addToast(id, url, "dast", url);

    saveRecent(url, "dast").then(() => loadRecent().then(setRecent));

    invoke<{ url: string; cachePath: string }>("start_agentic_dast", {
      url,
      tier: agTier,
      environment: agEnv,
      acceptSideEffects: agAck,
      greyBox: agGreyBox,
      focus: agFocus,
      identities: agIdentities.filter((i) => i.name.trim() && i.header.trim()),
      apiSpec: agApiSpec.trim(),
      requireApproval: agRequireApproval,
      allowEndpoints: agAllowEndpoints.split("\n").map((s) => s.trim()).filter(Boolean),
      denyEndpoints: agDenyEndpoints.split("\n").map((s) => s.trim()).filter(Boolean),
      limitToAllowlist: agLimitToAllowlist,
      allowDangerous: agAllowDangerous,
      attackTemplate: agTemplate
        ? { title: agTemplate.title, technique: agTemplate.technique, body: agTemplate.prompt_body }
        : null,
    })
      .then(async ({ url: rUrl, cachePath }) => {
        updateToastDone(id, rUrl, cachePath);
        await updateRecentUrl(url, rUrl);
        await updateRecentCachePath(url, cachePath);
        setRecent(await loadRecent());
        // Auto-navigate to the live run view (the embedded UI self-routes to it).
        openReport(rUrl, url, "dast");
      })
      .catch((e) => {
        const msg = String(e);
        if (msg.includes("__cancelled__")) return;
        if (msg.includes("__consent__")) {
          const domain = msg.split("__consent__")[1]?.trim() || "the target";
          updateToastError(id, `Prove you own ${domain} first — verification steps are in the terminal panel below.`);
          return;
        }
        updateToastError(id, friendlyError(msg));
      });
  }

  function openReport(url: string, path: string, type: ScanType): void {
    setScanPath(path);
    setScanType(type);
    setReportUrl(url);
    setView("report");
    // Clear any prior pen-test report so a stale grade can't print for a new target.
    setPentestReport(null);
    setDastFindings([]);
  }

  // Generate the graded, stakeholder-facing penetration-test report: pull the
  // latest findings from the report server, ask the (server-side cached)
  // pentest-report edge function for a grade + narrative, then open the print
  // dialog so it can be saved as PDF. A cache hit costs zero tokens.
  async function generatePentestReport(url: string): Promise<void> {
    if (pentestReportRunning) return;
    setPentestReportRunning(true);
    const id = crypto.randomUUID();
    addToast(id, scanPath, "dast", scanPath);
    try {
      const scanRes = await fetch(`${url}/api/scans/latest`);
      if (!scanRes.ok) throw new Error("Could not load findings from the report.");
      const scan = await scanRes.json();
      const findings: any[] = Array.isArray(scan?.findings) ? scan.findings : [];
      setDastFindings(findings);

      const token = await getFreshToken();
      if (!token) throw new Error("Sign in with Pro to generate a report.");

      const res = await fetch(`${SUPABASE_URL}/functions/v1/pentest-report`, {
        method: "POST",
        headers: { "Authorization": `Bearer ${token}`, "Content-Type": "application/json" },
        body: JSON.stringify({
          encoded: encodeBody({
            target: scan?.project_path ?? scanPath,
            findings: findings.map((f) => ({
              id: f.ID,
              title: f.Title,
              severity: String(f.Severity ?? "").toLowerCase(),
              verdict: f.Verdict,
              matchedAt: f.FilePath,
              evidence: f.CodeSnippet,
              rationale: f.RawMessage,
            })),
            user_familiarity: profile?.familiarity ?? 1,
          }),
        }),
      });
      if (res.status === 403) throw new Error("Sign in to generate reports.");
      if (res.status === 429) throw new Error("Daily AI limit reached. Try again tomorrow.");
      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error((err as { error?: string }).error ?? `Request failed (${res.status})`);
      }

      const report = await res.json() as PentestReport;
      setPentestReport(report);
      // This run just spent tokens (or confirmed a cache hit spent none) --
      // refresh rather than leave the sidebar showing the pre-run balance.
      void refreshTokenBalance();
      dismissToast(id);

      // Let the portal render with the report + findings, then open print → PDF.
      setTimeout(() => {
        const t = document.title;
        document.title = `Trojan Pen Test — ${scan?.project_path ?? scanPath}`;
        window.print();
        document.title = t;
      }, 150);
    } catch (e) {
      updateToastError(id, friendlyError(String(e)));
    } finally {
      setPentestReportRunning(false);
    }
  }

  function openRecent(r: RecentProject): void {
    if (r.cachePath && staleCaches.has(r.path)) {
      r.type === "sast" ? triggerSast(r.path) : triggerDast(r.path);
      return;
    }
    if (r.cachePath) {
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
  }

  // Load data from a previous scan without navigating away from the current view.
  // Used by Licenses, Privacy, and Compliance tabs.
  function loadScanData(r: RecentProject): void {
    if (!r.cachePath || staleCaches.has(r.path)) return;
    invoke<string>("serve_scan", { cachePath: r.cachePath })
      .then((url) => { fetchAndCachePackages(url); })
      .catch(() => {});
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

  // Upgrade CTA. Previously every one of these buttons called
  // setShowAuthForm(true), which meant an already-signed-in free user clicked
  // "Upgrade" and was handed a sign-in form for the account they were already
  // in -- a dead end on the three highest-intent surfaces in the app.
  //
  // Signed out is still the auth modal (that IS the right next step). Signed in
  // opens the web checkout in the system browser, because the checkout Edge
  // Function returns an embedded-Stripe clientSecret that requires Stripe.js in
  // a browser page.
  // Opens the web pricing page to buy tokens. Signed-out users get the auth
  // modal first, since a purchase has to attach to an account.
  function handleTopUp() {
    if (!authStatus?.loggedIn) {
      setShowAuthForm(true);
      return;
    }
    const toastId = `topup-${Date.now()}`;
    openUrl(`${MARKETING_URL}/pricing`).catch((e) => {
      addToast(toastId, "Buy tokens", "sast", "");
      updateToastError(toastId, friendlyError(String(e)));
    });
  }

  async function logout() {
    try {
      const s = await getStore();
      await s.clear();  // wipe all persisted keys (profile + recent projects)
      await s.save();   // force flush to disk so the next launch starts clean
    } catch {}
    // Clear local AI cache + config so stale explanations aren't reused
    invoke("clear_trojan_cache").catch(() => {});
    setProfile(null);
    setRecent([]);
    setCurrentServerUrl(null);
    setAuthStatus(null);
    setThreatLabResult(null);
    setPackages([]);
    setScanSummary(null);
    setReportUrl("");
    setMcpStatus({});
    setTokenBalance(null);
  }


  async function handlePickFolder() {
    const selected = await invoke<string | null>("pick_folder");
    if (selected) triggerSast(selected);
  }

  async function handleSetupMcp() {
    setMcpSetupBusy(true);
    try {
      await invoke("setup_mcp");
      const s = await invoke("check_mcp_status") as Record<string, { installed: boolean; configured: boolean }>;
      setMcpStatus(s);
    } catch {}
    setMcpSetupBusy(false);
  }

  // ── Gate renders ─────────────────────────────────────────────────────
  if (!profileLoaded) return null;

  if (!profile) return (
    <Onboarding
      onDone={(p) => onOnboardingDone(p, {
        setProfile,
        // Sync auth to ~/.trojan/config.json immediately so the Go sidecar
        // and the embedded report UI recognise the session on the first scan,
        // AND set in-memory authStatus -- every gate in the app (e.g. the
        // Penetration Testing tab) reads authStatus, not profile, so without
        // this the user would need to sign in a second time.
        syncAuthToGoConfig,
        applyAuthFromToken,
      })}
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
          <span className="sidebar-version">v{APP_VERSION}</span>
        </div>

        <nav className="sidebar-nav">
          {NAV.map(({ view: v, label, icon, pro, section }) => (
            <span key={v} style={{ display: "contents" }}>
              {section && <div className="sidebar-scan-label" style={{ marginTop: 8 }}>{section}</div>}
            <button
              className={`sidebar-nav-item ${view === v ? "active" : ""}`}
              onClick={() => setView(v)}
            >
              <span className="nav-icon">{icon}</span>
              <span style={{ flex: 1 }}>{label}</span>
              {pro && (
                <span style={{ fontFamily: "var(--font-sans)", fontWeight: 600, fontSize: 9, letterSpacing: "1px", color: "var(--accent-lift)", border: "1px solid rgba(167,139,250,0.4)", padding: "2px 5px" }}>PRO</span>
              )}
            </button>
            </span>
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

        {/* Token balance — only meaningful once signed in */}
        {authStatus?.loggedIn && (
          <div className="sidebar-bottom-actions" style={{ paddingBottom: 0 }}>
            <TokenBalance balance={tokenBalance} onTopUp={handleTopUp} />
          </div>
        )}

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

        {/* Feedback — reuses the terminal button's shape so it reads as another
            utility action rather than a promotion. Signed-in only: the edge
            function needs a bearer token to attribute the report. */}
        {authStatus?.loggedIn && (
          <div className="sidebar-bottom-actions" style={{ paddingTop: 0 }}>
            <button
              className="sidebar-terminal-btn"
              onClick={() => setShowFeedback(true)}
              title="Send feedback to the maintainer"
            >
              <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
                <path d="M21 11.5a8.38 8.38 0 0 1-.9 3.8 8.5 8.5 0 0 1-7.6 4.7 8.38 8.38 0 0 1-3.8-.9L3 21l1.9-5.7a8.38 8.38 0 0 1-.9-3.8 8.5 8.5 0 0 1 4.7-7.6 8.38 8.38 0 0 1 3.8-.9h.5a8.48 8.48 0 0 1 8 8v.5z"/>
              </svg>
              <span>Send feedback</span>
            </button>
          </div>
        )}

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
                {scanType === "dast" && reportUrl && (
                  <button
                    className="rescan-btn"
                    onClick={() => generatePentestReport(reportUrl)}
                    disabled={pentestReportRunning}
                    title="Generate a graded stakeholder report (PDF)"
                  >
                    {pentestReportRunning
                      ? <span className="lab-spinner" />
                      : <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z M14 2v6h6 M9 15l2 2 4-4"/></svg>}
                    {pentestReportRunning ? "Generating…" : "Generate Report"}
                  </button>
                )}
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
                {NAV.find((n) => n.view === view)?.label ?? (view === "threatlab" ? "Security Report" : view === "compliancelab" ? "Compliance Report" : "")}
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
            // Posture ring — the security score (higher = better) from the last report.
            const ringR   = 63;
            const ringC   = 2 * Math.PI * ringR;
            const secScore = threatLabResult ? Math.max(0, Math.min(100, 100 - threatLabResult.threat_index)) : null;
            const tGrade  = threatLabResult?.grade ?? null;
            const ringColor  = gradeColor(tGrade);
            const ringDash   = secScore !== null ? `${(ringC * secScore / 100).toFixed(1)} ${ringC.toFixed(1)}` : `0 ${ringC.toFixed(1)}`;

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
                  <button className="first-run-context-link" onClick={() => setView("context")}>
                    Set up your project context for smarter, privacy-aware scans {"→"}
                  </button>
                  <LocalPrivacyBadge compact />
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
                        {secScore !== null && <div className="posture-pulse" />}
                        <div className="posture-center">
                          {tGrade ? (
                            <>
                              <span className="posture-grade-text" style={{ color: ringColor }}>{tGrade}</span>
                              <span className="posture-score-text">{secScore}/100</span>
                            </>
                          ) : (
                            <span className="posture-empty-text">
                              {recent.length > 0 ? "Generate\na report" : "No scans\nyet"}
                            </span>
                          )}
                        </div>
                      </div>
                      {tGrade && <span className="posture-card-sub">Grade {tGrade} — {secScore} / 100</span>}
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
                        <span className="stat-value" style={{ color: vulnPkgs > 0 ? "var(--warning)" : undefined }}>
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
                        <div className="station-icon-wrap" style={{ color: "var(--blue)" }}>
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
                      <div className={`station-card ${isScanning ? "scan-locked" : ""}`} style={{ borderColor: "color-mix(in srgb, var(--primary) 12%, transparent)" }}>
                        <CM />
                        <div className="station-icon-wrap" style={{ color: "var(--primary)" }}>
                          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
                            <circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/>
                            <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/>
                          </svg>
                        </div>
                        <div>
                          <div className="station-code">STATION 02 — PENETRATION</div>
                          <div className="station-title">Penetration Testing</div>
                        </div>
                        <div className="station-desc">
                          Probe a live server: 6,618 Nuclei templates, CORS, headers, endpoint discovery.
                        </div>
                        <div className="station-tech">nuclei · cors · headers · endpoints</div>
                        <div className="station-footer">
                          <button className="station-btn" onClick={() => setView("dast")} disabled={isScanning}>
                            New pen test
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
              <div className="page-header">
                {recent.some(r => r.type === "sast" && r.cachePath) && (
                  <div className="page-header-row">
                    <button className="report-cta" onClick={() => setView("threatlab")} title="Generate an AI security report from your findings">
                      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z M14 2v6h6 M9 15l2 2 4-4"/></svg>
                      Generate Security Report
                    </button>
                  </div>
                )}
                <span className="page-header-eyebrow">SECURITY</span>
                <h1 className="page-header-title">Static Analysis</h1>
                <p className="page-header-desc">Scan a local project for vulnerabilities, secrets, and misconfigurations.</p>
              </div>

              {/* Context-aware scanning callout — surfaces the local org-context
                  feature without nagging. */}
              <button className="oc-feature-callout" onClick={() => setView("context")}>
                <span className="oc-feature-icon">
                  <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M9 12l2 2 4-4"/></svg>
                </span>
                <span className="oc-feature-text">
                  <span className="oc-feature-title">Context-aware scanning</span>
                  <span className="oc-feature-sub">Tell Trojan what you are building and it tests intentionally, for security and privacy. Stored on your machine, never uploaded.</span>
                </span>
                <span className="oc-feature-cta">Set up context {"→"}</span>
              </button>

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
                    { name: "Semgrep",  desc: "Pattern-based code analysis across 30+ languages.", icon: <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="var(--blue)" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"><path d="M10 4a6 6 0 1 0 0 12 6 6 0 0 0 0-12 M21 21l-6.65-6.65"/></svg> },
                    { name: "Trivy",    desc: "Known CVEs and misconfigurations in dependencies and images.", icon: <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="var(--blue)" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"><path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z"/></svg> },
                    { name: "Gitleaks", desc: "Hard-coded secrets, tokens and credentials in code and git history.", icon: <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="var(--blue)" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"><path d="M12.4 2.7a2.5 2.5 0 0 1 3.4 0l5.5 5.5a2.5 2.5 0 0 1 0 3.4l-3.7 3.7a2.5 2.5 0 0 1-3.4 0L8.7 9.8a2.5 2.5 0 0 1 0-3.4z M14 7l3 3 M9.4 10.6 2 18v4h4l7.4-7.4"/></svg> },
                    { name: "Checkov",  desc: "IaC policy checks — Terraform, CloudFormation, Kubernetes.", icon: <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="var(--blue)" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"><path d="M12 2 2 7l10 5 10-5-10-5 M2 17l10 5 10-5 M2 12l10 5 10-5"/></svg> },
                    { name: "Syft",     desc: "SBOM generation and license inventory for every artifact.", icon: <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="var(--blue)" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"><path d="M21 8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16Z M3.3 7l8.7 5 8.7-5 M12 22V12"/></svg> },
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
          {view === "market" && (
            <div className="content-inner">
              <AttackMarket
                getToken={async () => (await getFreshToken()) ?? ""}
                selectedSlug={agTemplate?.slug}
                onUseTemplate={(t) => { setAgTemplate(t); setView("dast"); }}
              />
            </div>
          )}

          {view === "dast" && (() => {
            // Signing in is the only requirement: a run is billed to an account. Whether
            // it can be AFFORDED is decided server-side against the token balance,
            // which returns 402 and pauses the run resumably rather than pre-blocking.
            const signedIn = authStatus?.loggedIn ?? false;
            return (
            <div className="content-inner">
              <div className="page-header">
                <span className="page-header-eyebrow">SECURITY</span>
                <h1 className="page-header-title">Penetration Testing <span className="lab-pro-tag">365 TOKENS</span></h1>
                <p className="page-header-desc">Scan a running server for runtime vulnerabilities using Nuclei's 6,000+ templates plus AI-generated attack patterns.</p>
              </div>

              {!signedIn && (
                <div className="lab-state-card lab-pro-gate">
                  <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
                  Sign in to run a penetration test. Every account gets 500 free tokens a month.
                  <button className="lab-upgrade-btn" onClick={() => setShowAuthForm(true)}>Sign in →</button>
                </div>
              )}

              {signedIn && (
              <>
              <div className={`pt-setup ${isScanning ? "scan-locked" : ""}`}>
                {/* Mode */}
                <span className="scanner-grid-label">MODE</span>
                <div className="pt-seg">
                  <button type="button" className={!agenticMode ? "on" : ""} onClick={() => setAgenticMode(false)} disabled={isScanning}>One-shot scan</button>
                  <button type="button" className={agenticMode ? "on" : ""} onClick={() => setAgenticMode(true)} disabled={isScanning}>AI Agent <span className="pt-seg-sub">adaptive</span></button>
                </div>

                {/* Target */}
                <span className="scanner-grid-label" style={{ marginTop: 16 }}>TARGET</span>
                <form className="dast-row-form" onSubmit={(e) => { e.preventDefault(); (agenticMode ? triggerAgenticDast : triggerDast)(dastUrl); }}>
                  <input
                    className="dast-input dast-input-lg"
                    type="url"
                    placeholder="https://staging.example.com"
                    value={dastUrl}
                    onChange={(e) => setDastUrl(e.target.value)}
                    disabled={isScanning}
                    autoFocus
                    style={{ fontFamily: "var(--font-mono)" }}
                  />
                  <button type="submit" className="station-btn" disabled={isScanning || !dastUrl.trim()} style={{ whiteSpace: "nowrap", padding: "0 22px" }}>
                    {isScanning ? "Scan in progress…" : "Launch pen test"}
                  </button>
                </form>
                <div className="pt-authnote">
                  <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round">
                    <path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3 M12 9v4 M12 17h.01"/>
                  </svg>
                  Only test systems you own or are authorized to test.
                </div>

                {/* Engagement — AI agent only */}
                {agenticMode && (
                  <>
                    {/* Cost guidance. A RANGE, not a point estimate: run cost
                        depends on how many steps the agent takes and how large
                        the crawled surface is, so one number would read as a
                        promise and be wrong most of the time. */}
                    <span className="scanner-grid-label" style={{ marginTop: 18 }}>COST</span>
                    <RunCostHint balance={tokenBalance} model="sonnet" />

                    {agTemplate && (
                      <div className="pt-template-banner">
                        <div className="pt-template-meta">
                          <span className="pt-template-tag">ATTACK TEMPLATE</span>
                          <span className="pt-template-name">{agTemplate.title}</span>
                        </div>
                        <button type="button" className="pt-template-clear" onClick={() => setAgTemplate(null)} disabled={isScanning}>Clear</button>
                      </div>
                    )}
                    <span className="scanner-grid-label" style={{ marginTop: 18 }}>ENGAGEMENT</span>
                    <div className="pt-eng-grid">
                      {/* Intensity ladder */}
                      <div className="pt-card">
                        <div className="pt-card-h">Intensity
                          <span className="pt-info" data-tip="How hard the agent pushes. Every level is non-destructive: single-proof, same-host only, no data dumped.">i</span>
                        </div>
                        {([
                          ["passive", "Passive", "Observe and fingerprint. GET probes only, zero side effects."],
                          ["safe-active", "Safe-active", "Adds state-changing probes, single-proof only. Never enumerates or dumps data."],
                          ["aggressive", "Aggressive", "Fuller payload coverage. Blocked on production targets."],
                        ] as const).map(([v, label, tip]) => {
                          const blocked = v === "aggressive" && agEnv === "production";
                          return (
                            <button
                              key={v}
                              type="button"
                              className={`pt-rung ${agTier === v ? "on" : ""}`}
                              onClick={() => setAgTier(v)}
                              disabled={isScanning || blocked}
                            >
                              <span className="pt-pip" />
                              <span className="pt-rung-t">
                                {label}
                                {v === "aggressive" && <span className="pt-tag-staging">staging only</span>}
                              </span>
                              <span className="pt-info" data-tip={tip}>i</span>
                            </button>
                          );
                        })}
                      </div>

                      {/* Right column: environment, grey-box, focus */}
                      <div className="pt-col">
                        <div className="pt-card">
                          <div className="pt-card-h">Environment
                            <span className="pt-info" data-tip="Production caps intensity to safe-active. Staging unlocks aggressive.">i</span>
                          </div>
                          <div className="pt-seg pt-seg-full">
                            <button type="button" className={agEnv === "production" ? "on" : ""} disabled={isScanning}
                              onClick={() => { setAgEnv("production"); if (agTier === "aggressive") setAgTier("passive"); }}>Production</button>
                            <button type="button" className={agEnv === "staging" ? "on" : ""} disabled={isScanning}
                              onClick={() => setAgEnv("staging")}>Staging</button>
                          </div>
                          {agTier === "safe-active" && agEnv === "production" && (
                            <label className="pt-ack">
                              <input type="checkbox" checked={agAck} onChange={(e) => setAgAck(e.target.checked)} disabled={isScanning} />
                              Accept possible side effects
                            </label>
                          )}
                        </div>

                        <div className="pt-card">
                          <div className="pt-row">
                            <span className="pt-card-h" style={{ margin: 0 }}>Grey-box
                              <span className="pt-info" data-tip="Reads this project's source to find the missing check (IDOR, SQLi, authz gaps) instead of guessing. Index, vectors and source stay on your machine; only the handler snippets the agent reads are sent to the AI, never stored.">i</span>
                            </span>
                            <button
                              type="button"
                              className={`pt-switch ${agGreyBox ? "" : "off"}`}
                              aria-pressed={agGreyBox}
                              aria-label="Toggle grey-box"
                              onClick={() => setAgGreyBox((v) => !v)}
                              disabled={isScanning}
                            />
                          </div>
                        </div>

                        <div className="pt-card">
                          <div className="pt-card-h">Focus
                            <span className="pt-info" data-tip="Narrows the agent to a technique set for fewer wasted probes. Optional.">i</span>
                          </div>
                          <div className="pt-chips">
                            {([["api", "API"], ["web", "Consumer web"], ["llm", "AI / LLM"]] as const).map(([v, label]) => (
                              <button
                                key={v}
                                type="button"
                                className={`pt-chip ${agFocus === v ? "on" : ""}`}
                                onClick={() => setAgFocus((f) => (f === v ? "" : v))}
                                disabled={isScanning}
                              >{label}</button>
                            ))}
                          </div>
                        </div>
                      </div>
                    </div>

                    {/* Identities — for authorization (IDOR/BOLA) testing */}
                    <div className="pt-idhead">
                      <span className="scanner-grid-label" style={{ margin: 0 }}>IDENTITIES</span>
                      <span className="pt-info" data-tip="Supply two or more logged-in sessions (name + an auth header like 'Authorization: Bearer ...'). The agent requests the same resource as each and compares, to catch broken object-level authorization.">i</span>
                    </div>
                    <div className="pt-card">
                      {agIdentities.length === 0 && (
                        <p className="pt-idhint">Add two or more sessions to test whether one user can reach another's data.</p>
                      )}
                      {agIdentities.map((id, i) => (
                        <div className="pt-id-row" key={i}>
                          <input
                            className="pt-id-name" placeholder="name" value={id.name} disabled={isScanning}
                            onChange={(e) => setAgIdentities((rows) => rows.map((r, j) => j === i ? { ...r, name: e.target.value } : r))}
                          />
                          <input
                            className="pt-id-header" placeholder="Authorization: Bearer ..." value={id.header} disabled={isScanning}
                            onChange={(e) => setAgIdentities((rows) => rows.map((r, j) => j === i ? { ...r, header: e.target.value } : r))}
                          />
                          <button type="button" className="pt-id-rm" aria-label="Remove identity" disabled={isScanning}
                            onClick={() => setAgIdentities((rows) => rows.filter((_, j) => j !== i))}>×</button>
                        </div>
                      ))}
                      <button type="button" className="pt-add" disabled={isScanning}
                        onClick={() => setAgIdentities((rows) => [...rows, { name: "", header: "" }])}>+ Add identity</button>
                    </div>

                    {/* API spec — expand the surface beyond what the crawler links (§6.5 #4) */}
                    <div className="pt-idhead">
                      <span className="scanner-grid-label" style={{ margin: 0 }}>API SPEC</span>
                      <span className="pt-info" data-tip="Point to an OpenAPI/Swagger file (path) or URL to test endpoints the crawler can't reach by following links — including unlinked admin/versioned routes and the params each takes. Leave blank to auto-probe common spec URLs on the target.">i</span>
                    </div>
                    <div className="pt-card">
                      <input
                        className="pt-id-header" style={{ width: "100%" }}
                        placeholder="path/to/openapi.yaml or https://target/openapi.json (optional)"
                        value={agApiSpec} disabled={isScanning}
                        onChange={(e) => setAgApiSpec(e.target.value)}
                      />
                      <p className="pt-idhint">Optional. Blank = auto-probe /openapi.json, /swagger.json, /v3/api-docs on the target.</p>
                    </div>

                    {/* Rules of engagement + human-in-the-loop (§8) */}
                    <div className="pt-idhead">
                      <span className="scanner-grid-label" style={{ margin: 0 }}>RULES OF ENGAGEMENT</span>
                      <span className="pt-info" data-tip="Require approval pauses the agent before every state-changing request so you approve or deny it in the run view. Allow/deny lists scope which endpoints it may touch (one path per line; trailing * = prefix). Read-only probes always run automatically.">i</span>
                    </div>
                    <div className="pt-card" style={{ display: "flex", flexDirection: "column", gap: 10 }}>
                      <label className="pt-roe-check">
                        <input type="checkbox" checked={agRequireApproval} disabled={isScanning}
                          onChange={(e) => setAgRequireApproval(e.target.checked)} />
                        <span>Require my approval before state-changing actions</span>
                      </label>
                      <div>
                        <p className="pt-idhint" style={{ marginTop: 0 }}>Allowed endpoints (one per line, trailing * = prefix; blank = all in scope)</p>
                        <textarea
                          className="pt-id-header" style={{ width: "100%", minHeight: 46, resize: "vertical", fontFamily: "var(--font-mono)" }}
                          placeholder={"/api/*\n/orders/*"}
                          value={agAllowEndpoints} disabled={isScanning}
                          onChange={(e) => setAgAllowEndpoints(e.target.value)}
                        />
                      </div>
                      <div>
                        <p className="pt-idhint" style={{ marginTop: 0 }}>Denied endpoints (never touched)</p>
                        <textarea
                          className="pt-id-header" style={{ width: "100%", minHeight: 46, resize: "vertical", fontFamily: "var(--font-mono)" }}
                          placeholder={"/admin/*\n/internal/*"}
                          value={agDenyEndpoints} disabled={isScanning}
                          onChange={(e) => setAgDenyEndpoints(e.target.value)}
                        />
                      </div>
                      <label className="pt-roe-check">
                        <input type="checkbox" checked={agLimitToAllowlist} disabled={isScanning || !agAllowEndpoints.trim()}
                          onChange={(e) => setAgLimitToAllowlist(e.target.checked)} />
                        <span>Hard-limit to the allowed list (block everything else)</span>
                      </label>
                      <label className="pt-roe-check">
                        <input type="checkbox" checked={agAllowDangerous} disabled={isScanning}
                          onChange={(e) => setAgAllowDangerous(e.target.checked)} />
                        <span>Allow dangerous patterns (account deletion, password/credential, payment)</span>
                      </label>
                    </div>
                  </>
                )}
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
              </>
              )}
            </div>
            );
          })()}

          {/* ── Licenses ── */}
          {view === "licenses" && (
            <div className="content-inner">
              <div className="page-header">
                <span className="page-header-eyebrow">COMPLIANCE</span>
                <h1 className="page-header-title">License Compliance</h1>
                <p className="page-header-desc">Open-source license risk across your dependency tree. Copyleft licenses may require you to open-source your code.</p>
              </div>
              {packages.length === 0 ? (
                <div className="lab-state-card">
                  <p className="lab-no-data" style={{ marginBottom: recent.filter(r => r.cachePath).length > 0 ? 10 : 0 }}>No license data loaded.</p>
                  {recent.filter(r => r.cachePath && r.type === "sast").length > 0 && (
                    <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
                      <span style={{ fontSize: 11, color: "var(--muted-fg)", fontWeight: 500 }}>LOAD FROM PREVIOUS SCAN</span>
                      {recent.filter(r => r.cachePath && r.type === "sast").slice(0, 5).map(r => (
                        <button key={r.path} onClick={() => loadScanData(r)} style={{ background: "none", border: "1px solid var(--border)", padding: "6px 10px", cursor: "pointer", fontSize: 12, color: "var(--fg)", textAlign: "left", display: "flex", justifyContent: "space-between" }}>
                          <span>{r.name}</span>
                          <span style={{ color: "var(--muted-fg)", fontSize: 11 }}>{timeAgo(r.scannedAt)}</span>
                        </button>
                      ))}
                    </div>
                  )}
                </div>
              ) : (() => {
                const LIC_PAGE = 50;
                const codebase = scanPath?.split("/").pop() ?? "project";
                const copyleft = packages.filter(p => p.license_risk === "copyleft");
                const weakCopyleft = packages.filter(p => p.license_risk === "weak-copyleft");
                const unknown = packages.filter(p => p.license_risk === "unknown" || !p.license_risk);
                const permissive = packages.filter(p => p.license_risk === "permissive");
                const sections = [
                  { key: "copyleft", label: "COPYLEFT — may require open-sourcing", items: copyleft, color: licenseRiskColor("copyleft") },
                  { key: "weak", label: "WEAK COPYLEFT — review modification terms", items: weakCopyleft, color: licenseRiskColor("weak-copyleft") },
                  { key: "unknown", label: "UNKNOWN — no license declared", items: unknown, color: licenseRiskColor("unknown") },
                  { key: "permissive", label: "PERMISSIVE — safe to use", items: permissive, color: licenseRiskColor("permissive") },
                ];
                return (
                  <>
                    {/* Loaded codebase bar */}
                    <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", padding: "8px 14px", background: "white", border: "1px solid var(--border)", marginBottom: 16 }}>
                      <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                        <span style={{ fontSize: 12, color: "var(--muted-fg)" }}>Analysing</span>
                        <span style={{ fontSize: 13, fontWeight: 600, color: "var(--fg)" }}>{codebase}</span>
                        <span style={{ fontSize: 11, color: "var(--muted-fg)" }}>{packages.length} package{packages.length !== 1 ? "s" : ""}</span>
                      </div>
                      <button onClick={() => { setPackages([]); setLicPages({}); }} style={{ background: "none", border: "1px solid var(--border)", padding: "4px 10px", cursor: "pointer", fontSize: 11, color: "var(--muted-fg)" }}>
                        Scan another project
                      </button>
                    </div>
                    <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 10, marginBottom: 16 }}>
                      {[
                        { label: "Copyleft", count: copyleft.length, color: licenseRiskColor("copyleft") },
                        { label: "Weak Copyleft", count: weakCopyleft.length, color: licenseRiskColor("weak-copyleft") },
                        { label: "Unknown", count: unknown.length, color: licenseRiskColor("unknown") },
                        { label: "Permissive", count: permissive.length, color: licenseRiskColor("permissive") },
                      ].map(s => (
                        <div key={s.label} className="lab-card" style={{ textAlign: "center", padding: 14 }}>
                          <div style={{ fontSize: 24, fontWeight: 700, color: s.color }}>{s.count}</div>
                          <div className="lab-card-label" style={{ marginTop: 4 }}>{s.label.toUpperCase()}</div>
                        </div>
                      ))}
                    </div>
                    {sections.filter(s => s.items.length > 0).map(s => {
                      const page = licPages[s.key] ?? 0;
                      const totalPages = Math.ceil(s.items.length / LIC_PAGE);
                      const pageItems = s.items.slice(page * LIC_PAGE, (page + 1) * LIC_PAGE);
                      return (
                        <div key={s.key} style={{ marginBottom: 16 }}>
                          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 8 }}>
                            <div className="lab-card-label" style={{ color: s.color }}>{s.label}</div>
                            {totalPages > 1 && (
                              <div style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 11, color: "var(--muted-fg)" }}>
                                <button disabled={page === 0} onClick={() => setLicPages(p => ({ ...p, [s.key]: page - 1 }))} style={{ background: "none", border: "1px solid var(--border)", padding: "2px 8px", cursor: page === 0 ? "default" : "pointer", opacity: page === 0 ? 0.4 : 1, fontSize: 11 }}>←</button>
                                <span>{page + 1} / {totalPages}</span>
                                <button disabled={page >= totalPages - 1} onClick={() => setLicPages(p => ({ ...p, [s.key]: page + 1 }))} style={{ background: "none", border: "1px solid var(--border)", padding: "2px 8px", cursor: page >= totalPages - 1 ? "default" : "pointer", opacity: page >= totalPages - 1 ? 0.4 : 1, fontSize: 11 }}>→</button>
                              </div>
                            )}
                          </div>
                          <div className="lab-card" style={{ padding: 0 }}>
                            {pageItems.map((p, i) => (
                              <div key={`${p.name}-${p.version}-${i}`} style={{ display: "flex", alignItems: "center", gap: 10, padding: "8px 14px", borderBottom: i < pageItems.length - 1 ? "1px solid var(--border)" : "none", fontSize: 13 }}>
                                <span style={{ fontWeight: 500, color: "var(--fg)", flex: 1 }}>{p.name}</span>
                                <span style={{ fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--muted-fg)" }}>{p.version}</span>
                                <span style={{ fontFamily: "var(--font-mono)", fontSize: 10, color: s.color, border: `1px solid ${s.color}33`, padding: "2px 6px" }}>{p.license || "NONE"}</span>
                              </div>
                            ))}
                          </div>
                        </div>
                      );
                    })}
                  </>
                );
              })()}
            </div>
          )}

          {/* ── Privacy ── */}
          {view === "privacy" && (() => {
            const dataTypes = privacyReport?.data_types ?? [];
            const thirdParty = privacyReport?.third_party ?? [];
            const codebase = scanPath?.split("/").pop() ?? "";
            const toggle = (key: string) => setExpandedPrivacy(prev => { const n = new Set(prev); n.has(key) ? n.delete(key) : n.add(key); return n; });

            return (
            <div className="content-inner">
              <div className="page-header">
                <span className="page-header-eyebrow">COMPLIANCE</span>
                <h1 className="page-header-title">Privacy Data Flows</h1>
                <p className="page-header-desc">Where personal data is processed in your code and which third-party services receive it.</p>
              </div>

              {!privacyReport ? (
                <div className="lab-state-card">
                  <p className="lab-no-data" style={{ marginBottom: recent.filter(r => r.cachePath && r.type === "sast").length > 0 ? 10 : 0 }}>No privacy data loaded.</p>
                  {recent.filter(r => r.cachePath && r.type === "sast").length > 0 && (
                    <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
                      <span style={{ fontSize: 11, color: "var(--muted-fg)", fontWeight: 500 }}>LOAD FROM PREVIOUS SCAN</span>
                      {recent.filter(r => r.cachePath && r.type === "sast").slice(0, 5).map(r => (
                        <button key={r.path} onClick={() => loadScanData(r)} style={{ background: "none", border: "1px solid var(--border)", padding: "6px 10px", cursor: "pointer", fontSize: 12, color: "var(--fg)", textAlign: "left", display: "flex", justifyContent: "space-between" }}>
                          <span>{r.name}</span>
                          <span style={{ color: "var(--muted-fg)", fontSize: 11 }}>{timeAgo(r.scannedAt)}</span>
                        </button>
                      ))}
                    </div>
                  )}
                </div>
              ) : (
                <>
                  {/* Loaded codebase bar */}
                  <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", padding: "8px 14px", background: "white", border: "1px solid var(--border)", marginBottom: 16 }}>
                    <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                      <span style={{ fontSize: 12, color: "var(--muted-fg)" }}>Analysing</span>
                      <span style={{ fontSize: 13, fontWeight: 600, color: "var(--fg)" }}>{codebase || "project"}</span>
                      <span style={{ fontSize: 11, color: "var(--muted-fg)" }}>{dataTypes.length} data type{dataTypes.length !== 1 ? "s" : ""}, {thirdParty.length} third part{thirdParty.length !== 1 ? "ies" : "y"}</span>
                    </div>
                    <button onClick={() => { setPrivacyReport(null); setExpandedPrivacy(new Set()); }} style={{ background: "none", border: "1px solid var(--border)", padding: "4px 10px", cursor: "pointer", fontSize: 11, color: "var(--muted-fg)" }}>
                      Scan another project
                    </button>
                  </div>

                  {/* Summary cards */}
                  <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 10, marginBottom: 16 }}>
                    <div className="lab-card" style={{ textAlign: "center", padding: 14 }}>
                      <div style={{ fontSize: 24, fontWeight: 700, color: "var(--primary)" }}>{dataTypes.length}</div>
                      <div className="lab-card-label" style={{ marginTop: 4 }}>PII TYPES DETECTED</div>
                    </div>
                    <div className="lab-card" style={{ textAlign: "center", padding: 14 }}>
                      <div style={{ fontSize: 24, fontWeight: 700, color: "var(--warning)" }}>{thirdParty.length}</div>
                      <div className="lab-card-label" style={{ marginTop: 4 }}>THIRD-PARTY RECIPIENTS</div>
                    </div>
                    <div className="lab-card" style={{ textAlign: "center", padding: 14 }}>
                      <div style={{ fontSize: 24, fontWeight: 700, color: "var(--destructive)" }}>{dataTypes.reduce((s, d) => s + d.detection_count, 0)}</div>
                      <div className="lab-card-label" style={{ marginTop: 4 }}>TOTAL DETECTIONS</div>
                    </div>
                  </div>

                  {/* Data types — expandable */}
                  <div style={{ marginBottom: 16 }}>
                    <div className="lab-card-label" style={{ marginBottom: 8 }}>PERSONAL DATA DETECTED</div>
                    {dataTypes.length === 0 ? (
                      <div className="lab-card" style={{ padding: 14, fontSize: 13, color: "var(--muted-fg)" }}>No personal data flows detected in this codebase.</div>
                    ) : (
                      <div className="lab-card" style={{ padding: 0 }}>
                        {dataTypes.map((dt, i) => {
                          const key = `dt-${dt.name}-${i}`;
                          const isOpen = expandedPrivacy.has(key);
                          return (
                            <div key={key} style={{ borderBottom: i < dataTypes.length - 1 ? "1px solid var(--border)" : "none" }}>
                              <div
                                onClick={() => toggle(key)}
                                style={{ display: "flex", alignItems: "center", gap: 8, padding: "10px 14px", cursor: "pointer" }}
                              >
                                <svg width="10" height="10" viewBox="0 0 10 10" style={{ transform: isOpen ? "rotate(90deg)" : "none", transition: "transform 0.15s", flexShrink: 0 }}>
                                  <path d="M3 1l4 4-4 4" fill="none" stroke="var(--muted-fg)" strokeWidth="1.5" />
                                </svg>
                                <span style={{ fontWeight: 500, fontSize: 13, color: "var(--fg)", flex: 1 }}>{dt.name}</span>
                                <span style={{ fontSize: 10, fontFamily: "var(--font-mono)", color: "var(--primary)", border: "1px solid rgba(124,58,237,0.3)", padding: "2px 5px" }}>{dt.category}</span>
                                {dt.category_groups?.map(g => (
                                  <span key={g} style={{ fontSize: 9, fontFamily: "var(--font-mono)", color: "var(--muted-fg)", border: "1px solid var(--border)", padding: "1px 4px" }}>{g}</span>
                                ))}
                                <span style={{ fontSize: 11, color: "var(--muted-fg)" }}>{dt.detection_count} detection{dt.detection_count !== 1 ? "s" : ""}</span>
                              </div>
                              {isOpen && dt.locations?.length > 0 && (
                                <div style={{ padding: "0 14px 10px 32px", display: "flex", flexDirection: "column", gap: 3 }}>
                                  <div style={{ fontSize: 10, fontWeight: 500, color: "var(--muted-fg)", letterSpacing: "0.05em", marginBottom: 2 }}>FILE LOCATIONS</div>
                                  {dt.locations.map((loc, j) => (
                                    <span key={j} style={{ fontSize: 11, fontFamily: "var(--font-mono)", color: "var(--fg)" }}>
                                      {loc.file}:{loc.line}
                                    </span>
                                  ))}
                                </div>
                              )}
                            </div>
                          );
                        })}
                      </div>
                    )}
                  </div>

                  {/* Third-party recipients — expandable */}
                  {thirdParty.length > 0 && (
                    <div>
                      <div className="lab-card-label" style={{ marginBottom: 8 }}>THIRD-PARTY DATA RECIPIENTS</div>
                      <div className="lab-card" style={{ padding: 0 }}>
                        {thirdParty.map((tp, i) => {
                          const key = `tp-${tp.name}-${i}`;
                          const isOpen = expandedPrivacy.has(key);
                          const dtList = (tp.data_types ?? []).filter(d => d !== "Unknown");
                          return (
                            <div key={key} style={{ borderBottom: i < thirdParty.length - 1 ? "1px solid var(--border)" : "none" }}>
                              <div
                                onClick={() => toggle(key)}
                                style={{ display: "flex", alignItems: "center", gap: 10, padding: "10px 14px", cursor: "pointer" }}
                              >
                                <svg width="10" height="10" viewBox="0 0 10 10" style={{ transform: isOpen ? "rotate(90deg)" : "none", transition: "transform 0.15s", flexShrink: 0 }}>
                                  <path d="M3 1l4 4-4 4" fill="none" stroke="var(--muted-fg)" strokeWidth="1.5" />
                                </svg>
                                <span style={{ fontWeight: 500, fontSize: 13, color: "var(--fg)" }}>{tp.name}</span>
                                <span style={{ fontSize: 11, color: "var(--muted-fg)", flex: 1 }}>{dtList.length > 0 ? dtList.join(", ") : "Data types not identified"}</span>
                                {tp.risk_count > 0 && <span className="dep-sev-badge dep-sev-medium" style={{ fontSize: 10 }}>{tp.risk_count} risk{tp.risk_count !== 1 ? "s" : ""}</span>}
                              </div>
                              {isOpen && (
                                <div style={{ padding: "0 14px 10px 32px", fontSize: 12, color: "var(--muted-fg)", lineHeight: 1.6 }}>
                                  <div style={{ fontSize: 10, fontWeight: 500, color: "var(--muted-fg)", letterSpacing: "0.05em", marginBottom: 4 }}>DATA SHARED</div>
                                  {dtList.length > 0 ? dtList.map(d => <div key={d}>- {d}</div>) : <div>Could not determine specific data types shared with this service.</div>}
                                  {tp.risk_count > 0 && <div style={{ marginTop: 6, color: "var(--warning)" }}>{tp.risk_count} privacy rule{tp.risk_count !== 1 ? "s" : ""} flagged for this integration.</div>}
                                </div>
                              )}
                            </div>
                          );
                        })}
                      </div>
                    </div>
                  )}
                </>
              )}
            </div>
            );
          })()}


          {/* ── Compliance Lab ── */}
          {view === "compliancelab" && (() => {
            // Signing in is the only requirement: a run is billed to an account. Whether
            // it can be AFFORDED is decided server-side against the token balance,
            // which returns 402 and pauses the run resumably rather than pre-blocking.
            const signedIn = authStatus?.loggedIn ?? false;
            const hasData = packages.length > 0;
            const codebaseName = scanPath?.split("/").pop() ?? "Unknown";
            const r = complianceLabResult;
            const gradeColorVal = gradeColor(r?.grade);
            const ringC = 2 * Math.PI * 50;

            async function runComplianceLab() {
              setComplianceLabRunning(true);
              setComplianceLabError(null);
              try {
                const token = await getFreshToken();
                if (!token) throw new Error("Sign in to generate a compliance report");

                const copyleft = packages.filter(p => p.license_risk === "copyleft").map(p => ({ name: p.name, version: p.version, license: p.license || "" }));
                const weakCopyleft = packages.filter(p => p.license_risk === "weak-copyleft").map(p => ({ name: p.name, license: p.license || "" }));
                const unknownCount = packages.filter(p => p.license_risk === "unknown" || !p.license_risk).length;
                const permissiveCount = packages.filter(p => p.license_risk === "permissive").length;

                const res = await fetch(`${SUPABASE_URL}/functions/v1/compliance-lab`, {
                  method: "POST",
                  headers: { "Authorization": `Bearer ${token}`, "Content-Type": "application/json" },
                  body: JSON.stringify({
                    encoded: encodeBody({
                      project_path: scanPath ?? "",
                      licenses: { total_packages: packages.length, copyleft, weak_copyleft: weakCopyleft, unknown_count: unknownCount, permissive_count: permissiveCount },
                      privacy: { data_types: (privacyReport?.data_types ?? []).map(d => ({ name: d.name, category: d.category, detection_count: d.detection_count })), third_party: (privacyReport?.third_party ?? []).map(t => ({ name: t.name, data_types: t.data_types ?? [] })) },
                      user_familiarity: profile?.familiarity ?? 1,
                    }),
                  }),
                });

                if (res.status === 403) throw new Error("Sign in to generate a compliance report. Costs 50 tokens.");
                if (res.status === 429) throw new Error("Daily limit reached. Try again tomorrow.");
                if (!res.ok) { const err = await res.json().catch(() => ({})); throw new Error((err as { error?: string }).error ?? `Request failed (${res.status})`); }

                setComplianceLabResult(await res.json() as ComplianceLabResult);
                // This run just spent tokens (or confirmed a cache hit spent none) --
                // refresh rather than leave the sidebar showing the pre-run balance.
                void refreshTokenBalance();
              } catch (e) {
                setComplianceLabError(friendlyError(String(e)));
              } finally {
                setComplianceLabRunning(false);
              }
            }

            return (
              <div className="content-inner lab-content" style={{ background: "var(--content-bg)" }}>
                <div className="lab-header-row">
                  <div>
                    <button className="lab-back" onClick={() => setView("dependencies")}>← Dependencies</button>
                    <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 3 }}>
                      <span className="lab-title-text">Compliance Report</span>
                      <span className="lab-pro-tag">50 TOKENS</span>
                    </div>
                    <p className="lab-subtitle">
                      {r && scanPath
                        ? `Compliance assessment for ${codebaseName}: licensing, privacy, and data handling.`
                        : "AI compliance assessment from your license analysis and privacy data flows."}
                    </p>
                  </div>
                  <div className="lab-header-actions">
                    {r && (
                      <button className="lab-export-btn" onClick={() => { const t = document.title; document.title = `Compliance Report - ${codebaseName}`; window.print(); document.title = t; }}>
                        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>
                        Export Report
                      </button>
                    )}
                    {hasData && signedIn && (
                      <button className={`lab-run-primary ${complianceLabRunning ? "lab-btn-loading" : ""}`} onClick={runComplianceLab} disabled={complianceLabRunning}>
                        {complianceLabRunning ? <><span className="lab-spinner" /> Analysing...</> : r ? "Re-generate" : "Generate report"}
                      </button>
                    )}
                  </div>
                </div>

                {!signedIn && (
                  <div className="lab-state-card lab-pro-gate">
                    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
                    Sign in to generate a compliance report. Costs 50 tokens.
                    <button className="lab-upgrade-btn" onClick={() => setShowAuthForm(true)}>Sign in →</button>
                  </div>
                )}

                {signedIn && !hasData && (
                  <div className="lab-state-card">
                    <p className="lab-no-data" style={{ marginBottom: recent.filter(r => r.cachePath).length > 0 ? 10 : 0 }}>Load scan data to generate a compliance report.</p>
                    {recent.filter(r => r.cachePath && r.type === "sast").length > 0 && (
                      <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
                        <span style={{ fontSize: 11, color: "var(--muted-fg)", fontWeight: 500 }}>LOAD FROM PREVIOUS SCAN</span>
                        {recent.filter(r => r.cachePath && r.type === "sast").slice(0, 5).map(r => (
                          <button key={r.path} onClick={() => loadScanData(r)} style={{ background: "none", border: "1px solid var(--border)", padding: "6px 10px", cursor: "pointer", fontSize: 12, color: "var(--fg)", textAlign: "left", display: "flex", justifyContent: "space-between" }}>
                            <span>{r.name}</span>
                            <span style={{ color: "var(--muted-fg)", fontSize: 11 }}>{timeAgo(r.scannedAt)}</span>
                          </button>
                        ))}
                      </div>
                    )}
                  </div>
                )}

                {signedIn && hasData && !r && !complianceLabRunning && (
                  <div className="lab-state-card">
                    <p className="lab-no-data">Scan data loaded for <strong>{codebaseName}</strong> ({packages.length} packages). Click "Generate report" for your AI compliance assessment.</p>
                  </div>
                )}

                {complianceLabError && <p className="lab-error">{complianceLabError}</p>}

                {r && (
                  <>
                    {/* Score row */}
                    <div className="lab-score-row-v2">
                      <div className="lab-index-card">
                        <div className="corner-marks"><i className="corner-mark cm-tl">+</i><i className="corner-mark cm-tr">+</i><i className="corner-mark cm-bl">+</i><i className="corner-mark cm-br">+</i></div>
                        <div className="lab-index-card-label">COMPLIANCE SCORE</div>
                        <div className="lab-index-ring-wrap">
                          <svg width="120" height="120" viewBox="0 0 120 120" style={{ transform: "rotate(-90deg)" }}>
                            <circle cx="60" cy="60" r="50" fill="none" stroke="var(--border)" strokeWidth="8" />
                            <circle cx="60" cy="60" r="50" fill="none" stroke={gradeColorVal} strokeWidth="8" strokeDasharray={`${(ringC * r.score / 100).toFixed(1)} ${ringC.toFixed(1)}`} />
                          </svg>
                          <div className="lab-ring-center">
                            <span className="lab-index-num">{r.score}</span>
                            <span className="lab-ring-denom">/100</span>
                          </div>
                        </div>
                        <div className="lab-index-sub2">higher = more compliant</div>
                      </div>

                      <div className="lab-grade-card">
                        <div className="lab-index-card-label">GRADE</div>
                        <div className="lab-grade-box">
                          <span className="lab-grade-letter" style={{ borderColor: gradeColorVal, color: gradeColorVal }}>{r.grade}</span>
                        </div>
                        <div className="lab-index-sub2">
                          {r.grade === "A" ? "excellent" : r.grade === "B" ? "good" : r.grade === "C" ? "fair" : r.grade === "D" ? "needs attention" : "critical"}
                        </div>
                      </div>

                      <div className="lab-verdict-card">
                        <div className="lab-index-card-label">EXECUTIVE SUMMARY</div>
                        <p className="lab-verdict-text">{r.executive_summary}</p>
                      </div>
                    </div>

                    {/* Verdicts */}
                    <div className="lab-body-cols">
                      <div className="lab-body-left">
                        <div className="lab-card">
                          <div className="lab-card-label">LICENSE ASSESSMENT</div>
                          <p style={{ fontSize: 12.5, color: "var(--fg)", lineHeight: 1.65, margin: 0 }}>{r.license_verdict}</p>
                        </div>
                      </div>
                      <div className="lab-body-right">
                        <div className="lab-card">
                          <div className="lab-card-label">PRIVACY & DATA HANDLING</div>
                          <p style={{ fontSize: 12.5, color: "var(--fg)", lineHeight: 1.65, margin: 0 }}>{r.privacy_verdict}</p>
                        </div>
                      </div>
                    </div>

                    {/* Recommendations */}
                    {r.recommendations && r.recommendations.length > 0 && (
                      <div className="lab-card" style={{ position: "relative" }}>
                        <div className="corner-marks"><i className="corner-mark cm-tl">+</i><i className="corner-mark cm-tr">+</i><i className="corner-mark cm-bl">+</i><i className="corner-mark cm-br">+</i></div>
                        <div className="lab-card-label">RECOMMENDATIONS</div>
                        {r.recommendations.map((rec, i) => (
                          <div key={i} className="lab-fix-v2" style={{ borderBottom: i < r.recommendations.length - 1 ? "1px solid var(--border)" : "none" }}>
                            <span className="lab-fix-rank">{i + 1}</span>
                            <p style={{ fontSize: 12.5, color: "var(--fg)", lineHeight: 1.55, margin: 0, flex: 1 }}>{rec}</p>
                          </div>
                        ))}
                      </div>
                    )}
                  </>
                )}
              </div>
            );
          })()}

          {/* ── History ── */}
          {view === "history" && (
            <div className="content-inner">
              <div className="page-header">
                <div className="page-header-row">
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
                  {recent.length > 0 && (
                    <button className="history-clear-all-btn" onClick={clearAllRecent}>
                      Clear all
                    </button>
                  )}
                </div>
                <span className="page-header-eyebrow">GENERAL</span>
                <h1 className="page-header-title">Scan History</h1>
                <p className="page-header-desc">
                  {recent.length > 0
                    ? `${recent.length} scan${recent.length !== 1 ? "s" : ""}, cached results re-open instantly.`
                    : "Every scan you've run, cached and ready to reopen without rescanning."}
                </p>
              </div>

              {(() => {
                const filteredRecent = historyFilter === "all" ? recent : recent.filter(r => r.type === historyFilter);
                return filteredRecent.length === 0 ? (
                  <div className="empty-state">
                    <p>Run your first scan from Overview or Static / Penetration Testing.</p>
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
              <div className="page-header">
                {packages.length > 0 && (
                  <div className="page-header-row">
                    <button className="report-cta" onClick={() => setView("compliancelab")} title="Generate an AI compliance report from your dependencies">
                      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z M14 2v6h6 M9 15l2 2 4-4"/></svg>
                      Generate Compliance Report
                    </button>
                  </div>
                )}
                <span className="page-header-eyebrow">SECURITY</span>
                <h1 className="page-header-title">Dependencies</h1>
                <p className="page-header-desc">
                  {packages.length > 0
                    ? `${packages.length} packages, ${packages.filter(p => p.cve_count > 0).length} with known CVEs.`
                    : "Every package in your project, its known CVEs, and the safe version to upgrade to."}
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
            // Signing in is the only requirement: a run is billed to an account. Whether
            // it can be AFFORDED is decided server-side against the token balance,
            // which returns 402 and pauses the run resumably rather than pre-blocking.
            const signedIn = authStatus?.loggedIn ?? false;
            const hasData = currentServerUrl != null;
            const r = threatLabResult;
            const gradeColorVal = gradeColor(r?.grade);
            // Ring: r=50, circumference=314.16. Score is flipped to "higher = better"
            // (a Security Score) so it reads intuitively and matches the A-F grade
            // and the Compliance Report. The edge fn still returns a threat_index.
            const ringC = 2 * Math.PI * 50;
            const securityScore = r ? Math.max(0, Math.min(100, 100 - r.threat_index)) : 0;
            const ringDash = r ? `${(ringC * securityScore / 100).toFixed(1)} ${ringC.toFixed(1)}` : `0 ${ringC.toFixed(1)}`;

            return (
              <div className="lab-content lab-print-area">

                {/* ── Header row ── */}
                <div className="lab-header-row">
                  <div>
                    <button className="lab-back" onClick={() => setView("sast")}>← Static Analysis</button>
                    <div className="lab-title-row">
                      <span className="lab-title-text">Security Report</span>
                      <span className="lab-pro-tag">100 TOKENS</span>
                    </div>
                    <p className="lab-subtitle">
                      {r && scanPath
                        ? `AI security assessment of ${scanPath.split("/").pop()}, from your SAST and dependency findings.`
                        : "AI security assessment from your SAST and dependency findings."}
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
                    {hasData && signedIn && (
                      <button
                        className={`lab-run-primary ${isLabRunning ? "lab-btn-loading" : ""}`}
                        onClick={runThreatLab}
                        disabled={isLabRunning}
                      >
                        {isLabRunning ? <><span className="lab-spinner" /> Analysing…</> : r ? "Re-generate" : "Generate report"}
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
                {hasData && !signedIn && (
                  <div className="lab-state-card lab-pro-gate">
                    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
                    Sign in to generate a security report. Costs 100 tokens.
                    <button className="lab-upgrade-btn" onClick={() => setShowAuthForm(true)}>Sign in →</button>
                  </div>
                )}
                {hasData && signedIn && !r && !isLabRunning && (
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
                        <div className="lab-index-card-label">SECURITY SCORE</div>
                        <div className="lab-index-ring-wrap">
                          <svg width="120" height="120" viewBox="0 0 120 120" style={{ transform: "rotate(-90deg)" }}>
                            <circle cx="60" cy="60" r="50" fill="none" stroke="var(--border)" strokeWidth="8" />
                            <circle cx="60" cy="60" r="50" fill="none" stroke={gradeColorVal} strokeWidth="8" strokeDasharray={ringDash} />
                          </svg>
                          <div className="lab-ring-center">
                            <span className="lab-index-num">{securityScore}</span>
                            <span className="lab-ring-denom">/100</span>
                          </div>
                        </div>
                        <div className="lab-index-sub2">higher = more secure</div>
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
                                background: i <= 1 ? "var(--destructive)" : "var(--warning)"
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

          {/* ── Fix with AI ── */}
          {view === "autofix" && (() => {
            const editors = [
              { key: "claude_code", label: "Claude Code", logo: "/claude-logo.png", desc: "Anthropic's coding agent" },
              { key: "cursor",      label: "Cursor",      logo: "/cursor-logo.png", desc: "AI-native code editor" },
              { key: "codex_cli",   label: "Codex CLI",   logo: "/openai-logo.webp", desc: "OpenAI's terminal agent" },
            ];
            const anyConfigured = editors.some(e => mcpStatus[e.key]?.configured);
            const connectedCount = editors.filter(e => mcpStatus[e.key]?.configured).length;

            // Both SAST and pen-test (DAST) scans are MCP-readable, so the editor
            // can pull findings from either — list both here.
            const fixScans = recent.filter(r => r.cachePath);
            const selectedScan = fixScans[fixScanIdx] ?? null;

            return (
              <div className="autofix-page">
                <div className="overview-grid-bg" />
                <div className="autofix-inner">

                  {/* Row 1: header + status badge */}
                  <div className="page-header">
                    <span className="page-header-eyebrow">GENERAL</span>
                    <h1 className="page-header-title">Fix with AI</h1>
                    <p className="page-header-desc">
                      Connect your editor so Trojan can hand off findings as ready-to-run fix prompts, all local via MCP.
                    </p>
                    <div className="page-header-actions">
                      <div className="overview-status-badge">
                        <span className={`status-dot ${anyConfigured ? "status-dot-ok" : "status-dot-warn"}`} />
                        {anyConfigured ? `${connectedCount} CONNECTED` : "NOT CONFIGURED"}
                      </div>
                    </div>
                  </div>

                  {/* Immersive MCP connection diagram */}
                  <McpConnect editors={editors} mcpStatus={mcpStatus} onConnect={handleSetupMcp} busy={mcpSetupBusy} />

                  {/* Scan selector */}
                  <div className="autofix-action-row">
                    <div className="autofix-scan-card">
                      <CM />
                      <div className="autofix-connect-card-code">SELECT SCAN</div>
                      <div className="autofix-connect-card-title">Target project</div>
                      {(() => {
                        const PER_PAGE = 5;
                        const totalPages = Math.ceil(fixScans.length / PER_PAGE);
                        const pageScans = fixScans.slice(fixScanPage * PER_PAGE, (fixScanPage + 1) * PER_PAGE);

                        if (fixScans.length === 0) return (
                          <div className="autofix-empty">
                            <p>No scans yet</p>
                            <button className="autofix-action-btn" onClick={handlePickFolder}>Run a scan</button>
                          </div>
                        );

                        return (
                          <>
                            <div className="autofix-scan-list">
                              {pageScans.map((s, i) => {
                                const globalIdx = fixScanPage * PER_PAGE + i;
                                return (
                                  <button
                                    key={s.path}
                                    className={`autofix-scan-item ${globalIdx === fixScanIdx ? "active" : ""}`}
                                    onClick={() => setFixScanIdx(globalIdx)}
                                  >
                                    <span className={`autofix-scan-typebadge ${s.type === "sast" ? "sast" : "dast"}`}>{s.type === "sast" ? "SAST" : "PEN TEST"}</span>
                                    <span className="autofix-scan-name">{s.name}</span>
                                    <span className="autofix-scan-time">{timeAgo(s.scannedAt)}</span>
                                  </button>
                                );
                              })}
                            </div>
                            {totalPages > 1 && (
                              <div className="autofix-scan-pager">
                                <button
                                  className="autofix-pager-btn"
                                  disabled={fixScanPage === 0}
                                  onClick={() => setFixScanPage(p => p - 1)}
                                >
                                  ←
                                </button>
                                <span className="autofix-pager-info">{fixScanPage + 1} / {totalPages}</span>
                                <button
                                  className="autofix-pager-btn"
                                  disabled={fixScanPage >= totalPages - 1}
                                  onClick={() => setFixScanPage(p => p + 1)}
                                >
                                  →
                                </button>
                              </div>
                            )}
                          </>
                        );
                      })()}
                    </div>
                  </div>

                  {/* Row 4: how it works + prompts side by side */}
                  <div className="autofix-bottom-row">
                    {/* Left: how it works */}
                    <div className="autofix-how-card">
                      <CM />
                      <div className="autofix-connect-card-code">HOW IT WORKS</div>
                      <div className="autofix-how-steps">
                        <div className="autofix-how-step">
                          <span className="autofix-how-num">1</span>
                          <div>
                            <strong>AI reads findings</strong>
                            <p>Calls <code>get_fixable_findings</code> — gets all vulnerabilities with surrounding code context.</p>
                          </div>
                        </div>
                        <div className="autofix-how-step">
                          <span className="autofix-how-num">2</span>
                          <div>
                            <strong>AI edits your code</strong>
                            <p>Applies targeted fixes using language, framework, and fix hints from Trojan.</p>
                          </div>
                        </div>
                        <div className="autofix-how-step">
                          <span className="autofix-how-num">3</span>
                          <div>
                            <strong>Marks findings resolved</strong>
                            <p>Calls <code>mark_fixed</code> to update scan results. Dashboard refreshes automatically.</p>
                          </div>
                        </div>
                      </div>
                    </div>

                    {/* Right: prompt suggestions */}
                    <div className="autofix-prompts-card">
                      <CM />
                      <div className="autofix-connect-card-code">SUGGESTED PROMPTS</div>
                      <div className="autofix-prompt-list">
                        <div className="autofix-prompt">
                          <code>"Fix all critical and high severity Trojan findings"</code>
                          <span className="autofix-prompt-tag">Start here</span>
                        </div>
                        <div className="autofix-prompt">
                          <code>"Show my Trojan findings and explain each one"</code>
                        </div>
                        <div className="autofix-prompt">
                          <code>"Fix the most critical finding and mark it resolved"</code>
                        </div>
                      </div>
                      <p className="autofix-prompts-hint">
                        Open your editor in{selectedScan && selectedScan.type === "sast" ? ` ${selectedScan.path}` : " the project directory"} and paste any prompt above.
                      </p>
                    </div>
                  </div>

                </div>
              </div>
            );
          })()}

          {/* ── Profile ── */}
          {/* ── Project Context (view + edit the local org context) ── */}
          {view === "context" && (
            <OrgContextEditor serverUrl={currentServerUrl} />
          )}

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
                        onChange={e => {
                          setProfile({ ...profile, aboutYou: e.target.value } as UserProfile);
                          setProfileSaved(false);
                          setProfileJustSaved(false);
                        }}
                      />
                      <span className="profile-hint">This context is used across all Trojan AI features — findings explanations, security reports, remediation advice, and more.</span>
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
                              onClick={() => { setProfile({ ...profile, familiarity: i } as UserProfile); setProfileSaved(false); setProfileJustSaved(false); }}
                            >
                              <span
                                className="profile-fam-dot"
                                style={{
                                  width:      i === fam ? 16 : 12,
                                  height:     i === fam ? 16 : 12,
                                  background: i <= fam ? "var(--primary)" : "var(--border)",
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
                                color:      i === fam ? "var(--accent-deep)" : "var(--muted-fg)",
                                fontWeight: i === fam ? 600 : 400,
                                textAlign:  i === 0 ? "left" : i === 1 ? "center" : "right",
                                cursor: "pointer",
                              }}
                              onClick={() => { setProfile({ ...profile, familiarity: i } as UserProfile); setProfileSaved(false); setProfileJustSaved(false); }}
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

                    <button
                      className={`profile-save-btn ${profileSaved ? "saved" : ""}`}
                      disabled={profileSaved}
                      onClick={() => {
                        saveProfile(profile);
                        invoke("sync_profile_context", {
                          familiarity: profile.familiarity ?? 1,
                          aboutYou: profile.aboutYou ?? "",
                        }).catch(() => {});
                        savedProfileRef.current = { aboutYou: profile.aboutYou ?? "", familiarity: profile.familiarity ?? 1 };
                        setProfileSaved(true);
                        setProfileJustSaved(true);
                        setTimeout(() => setProfileJustSaved(false), 2000);
                      }}
                    >
                      {profileJustSaved ? "Saved" : profileSaved ? "Preferences saved" : "Save preferences"}
                    </button>
                  </div>

                </div>
              </div>
            );
          })()}

          {/* ── Off-origin backstop ── */}
          {/* Should never show in practice now that external links route through
              the postMessage bridge, but if the report iframe ever ends up
              somewhere other than the report itself, this is the way back. */}
          {reportUrl && view === "report" && iframeOffOrigin && (
            <div className="report-offsite-banner">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
              <span>This report navigated outside the app.</span>
              <button
                className="report-offsite-btn"
                onClick={() => { restoreReport(iframeRef.current, reportUrl); setIframeOffOrigin(false); }}
              >
                ← Back to report
              </button>
            </div>
          )}

          {/* ── Scan report iframe ── */}
          {/* Always mounted when reportUrl is set so switching tabs doesn't trigger a reload */}
          {reportUrl && (
            <iframe
              ref={iframeRef}
              className="report-frame-inline"
              style={view !== "report" ? { display: "none" } : undefined}
              src={reportUrl}
              title="Trojan Security Report"
              onLoad={handleReportFrameLoad}
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

      {/* ── Feedback modal ── */}
      {showFeedback && (
        <div className="auth-overlay" onClick={() => setShowFeedback(false)}>
          <div className="auth-modal" onClick={(e) => e.stopPropagation()}>
            <CM />
            <div className="auth-modal-header">
              <h2 className="auth-modal-title">Send feedback</h2>
              <button className="auth-modal-close" onClick={() => setShowFeedback(false)} title="Close">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round">
                  <line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/>
                </svg>
              </button>
            </div>
            <FeedbackForm
              getToken={getFreshToken}
              appVersion={APP_VERSION}
              view={view}
              onSent={() => setShowFeedback(false)}
            />
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

      {/* Print portals — only one renders at a time based on current view */}
      {view !== "compliancelab" && !(view === "report" && scanType === "dast") && (
        <PrintCertificate
          projectPath={scanPath}
          scanSummary={scanSummary}
          threatLabResult={threatLabResult}
          packages={packages}
        />
      )}
      {view === "compliancelab" && (
        <PrintComplianceReport
          projectPath={scanPath}
          result={complianceLabResult}
          packages={packages}
        />
      )}
      {view === "report" && scanType === "dast" && (
        <PrintPenTestReport targetUrl={scanPath} findings={dastFindings} report={pentestReport} />
      )}

    </div>
  );
}
