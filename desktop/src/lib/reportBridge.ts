// Bridge between the sandboxed report iframe (ui/ or dast-ui/, built and
// served independently with zero Tauri imports) and the desktop shell.
//
// The report renders external links (pricing, dashboard, "sign in") as
// buttons that postMessage the parent instead of plain <a> tags. A plain
// anchor with no target navigates the IFRAME itself, stranding the user on
// trojancli.com with no way back (that was the "Upgrade Plan traps the
// user" bug). `target="_blank"` doesn't help either: the report runs in a
// Tauri webview with no new-window handler registered, so WKWebView just
// drops it silently.
//
// This listener is the parent-side half of that bridge. isIframeOffOrigin /
// restoreReport back it up with a defensive "back to report" control for
// anything that reaches a real navigation anyway (a stray link someone adds
// later, a redirect inside the served report, etc).

const MESSAGE_SOURCE = "trojan-report";
const MESSAGE_TYPE = "open-external";

interface ExternalLinkMessage {
  source: typeof MESSAGE_SOURCE;
  type: typeof MESSAGE_TYPE;
  url: string;
}

// Narrow shape of MessageEvent we actually need -- makes this testable
// without constructing a real MessageEvent/Window in jsdom.
export interface ExternalLinkEvent {
  data: unknown;
  source: MessageEventSource | Window | null;
}

// Strict check: rather than trusting `event.origin` (the report's origin is
// a per-scan local Go server on a random port -- there is no fixed origin to
// allowlist), we require the message to have come from the exact window
// object of OUR iframe. Nothing else in the page (an ad, a devtools
// extension, a future stray script) can spoof that identity.
export function extractExternalLinkUrl(
  event: ExternalLinkEvent,
  iframeWindow: Window | null,
): string | null {
  if (!iframeWindow || event.source !== iframeWindow) return null;
  const data = event.data as Partial<ExternalLinkMessage> | null | undefined;
  if (!data || data.source !== MESSAGE_SOURCE || data.type !== MESSAGE_TYPE) return null;
  return typeof data.url === "string" && data.url.length > 0 ? data.url : null;
}

// Factory so App.tsx can wire this straight into addEventListener("message", ...)
// while tests can call the returned listener directly with fake events.
export function createExternalLinkListener(
  getIframeWindow: () => Window | null,
  openExternalUrl: (url: string) => void,
): (event: ExternalLinkEvent) => void {
  return (event) => {
    const url = extractExternalLinkUrl(event, getIframeWindow());
    if (url) openExternalUrl(url);
  };
}

// True once the report iframe has navigated somewhere outside the report's
// own origin. Reading a cross-origin frame's location.href throws
// synchronously (SecurityError) -- that throw itself proves we've left the
// report, so it counts as off-origin too.
export function isIframeOffOrigin(reportUrl: string, readHref: () => string | null): boolean {
  if (!reportUrl) return false;
  try {
    const href = readHref();
    if (!href) return false;
    return new URL(href).origin !== new URL(reportUrl).origin;
  } catch {
    return true;
  }
}

// Restores the iframe to the last known-good report URL. Used by the "Back
// to report" control.
export function restoreReport(frame: { src: string } | null, reportUrl: string): void {
  if (frame && reportUrl) frame.src = reportUrl;
}
