// This report is built and served completely independently of the Tauri
// desktop shell (zero Tauri imports here, by design -- it must stay
// standalone-buildable and runnable directly in a browser during dev). The
// shell embeds it in a plain <iframe>, though, so a bare `<a href>` would
// navigate the IFRAME itself rather than the user's browser -- stranding
// them on trojancli.com with no way back -- and `target="_blank"` silently
// no-ops because the embedding webview has no new-window handler registered.
//
// So external links go through this tiny postMessage bridge instead: the
// parent shell (desktop/src/App.tsx) listens for this exact message shape
// and opens the URL in the user's real browser via Tauri's opener plugin.
export function openExternal(url: string): void {
  try {
    if (window.parent && window.parent !== window) {
      window.parent.postMessage({ source: "trojan-report", type: "open-external", url }, "*");
      return;
    }
  } catch {
    // fall through to the standalone fallback below
  }
  // Not embedded (e.g. `npm run dev` opened directly in a browser tab) --
  // there's no parent shell to ask, so just open a real new tab.
  window.open(url, "_blank", "noopener,noreferrer");
}
