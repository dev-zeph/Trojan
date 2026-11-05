import { useEffect, useState } from "react";
import type { ContextChanges, OrgContext } from "./types";
import { fetchContextChanges, fetchOrgContext } from "./lib/orgContext";
import { AppUnderstanding } from "./AppUnderstanding";

// A banner on the founder's project home. Two cases:
//  - Trojan has not learned about this project yet: offer the free first look.
//  - The app changed since Trojan last learned about it: offer an update.
// The check runs when the project is opened and again whenever `refreshKey`
// changes (the app bumps it after a scan finishes). No file watcher.

function pathOnly(route: string): string {
  const i = route.indexOf(" ");
  return i >= 0 ? route.slice(i + 1) : route;
}

export function describeChanges(c: ContextChanges): string[] {
  const out: string[] = [];
  const pages = [...c.routes_added.map(pathOnly)];
  if (pages.length) out.push(`New pages: ${pages.join(", ")}`);
  if (c.data_stores_added.length) out.push(`New places data is kept: ${c.data_stores_added.join(", ")}`);
  if (c.services_added.length) out.push(`New outside services: ${c.services_added.join(", ")}`);
  const gone = [...c.routes_removed.map(pathOnly), ...c.data_stores_removed, ...c.services_removed];
  if (gone.length) out.push(`No longer found: ${gone.join(", ")}`);
  return out;
}

export function ContextChangeBanner({
  serverUrl, projectPath, refreshKey = 0, onTopUp,
}: {
  serverUrl: string | null;
  projectPath: string;
  refreshKey?: number;
  onTopUp?: () => void;
}) {
  const [existing, setExisting] = useState<OrgContext | null>(null);
  const [kind, setKind] = useState<"none" | "learn" | "changed">("none");
  const [changes, setChanges] = useState<ContextChanges | null>(null);
  const [dismissed, setDismissed] = useState(false);
  const [open, setOpen] = useState(false);

  useEffect(() => {
    if (!serverUrl || !projectPath) { setKind("none"); return; }
    let cancelled = false;
    (async () => {
      try {
        const { exists, context } = await fetchOrgContext(serverUrl, projectPath);
        if (cancelled) return;
        if (!exists) { setExisting(null); setKind("learn"); setDismissed(false); return; }
        setExisting(context);
        const c = await fetchContextChanges(serverUrl, projectPath);
        if (cancelled) return;
        setChanges(c);
        setKind(c ? "changed" : "none");
        if (c) setDismissed(false);
      } catch {
        if (!cancelled) setKind("none");
      }
    })();
    return () => { cancelled = true; };
  }, [serverUrl, projectPath, refreshKey]);

  if (!serverUrl || !projectPath) return null;

  return (
    <>
      {kind !== "none" && !dismissed && (
        <div className="au-banner" role="status">
          <div className="au-banner-body">
            {kind === "learn" ? (
              <>
                <strong>Help Trojan learn about your app.</strong>
                <span>Its checks fit better when it knows what you built. The first time is free.</span>
              </>
            ) : (
              <>
                <strong>Your app changed since Trojan last learned about it. Update what Trojan knows?</strong>
                {changes && describeChanges(changes).map((line) => <span key={line}>{line}</span>)}
                <span>Updates use tokens.</span>
              </>
            )}
          </div>
          <div className="au-banner-actions">
            <button type="button" className="oc-nav-next" onClick={() => setOpen(true)}>
              {kind === "learn" ? "Tell Trojan about my app" : "Update what Trojan knows"}
            </button>
            <button type="button" className="au-link" onClick={() => setDismissed(true)}>Not now</button>
          </div>
        </div>
      )}
      {open && (
        <AppUnderstanding
          serverUrl={serverUrl}
          projectPath={projectPath}
          existing={existing}
          runsFree={kind === "learn"}
          onTopUp={onTopUp}
          onCancel={() => setOpen(false)}
          onDone={(saved) => { setExisting(saved); setKind("none"); setChanges(null); setOpen(false); }}
        />
      )}
    </>
  );
}
