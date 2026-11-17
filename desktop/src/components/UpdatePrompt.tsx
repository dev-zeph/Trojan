import { useCallback, useEffect, useRef, useState } from "react";
import { listen } from "@tauri-apps/api/event";
import { check, type Update } from "@tauri-apps/plugin-updater";
import { relaunch } from "@tauri-apps/plugin-process";
import "./UpdatePrompt.css";

/** How often to look again while the app stays open. */
export const UPDATE_CHECK_INTERVAL_MS = 4 * 60 * 60 * 1000;

interface Props {
  /** True while a scan is running. The prompt waits until it is false. */
  busy: boolean;
}

/** Quiet auto-update prompt. Checks GitHub Releases on launch and every few
 *  hours. Every failure is logged and swallowed: updates must never get in
 *  the way of the app. */
export function UpdatePrompt({ busy }: Props) {
  const [update, setUpdate] = useState<Update | null>(null);
  const [later, setLater] = useState(false);
  const [penTestRunning, setPenTestRunning] = useState(false);
  const [progress, setProgress] = useState<number | null>(null);
  const installing = useRef(false);

  useEffect(() => {
    let alive = true;
    async function run() {
      if (installing.current) return;
      try {
        const found = await check();
        if (alive && found) setUpdate((prev) => (prev?.version === found.version ? prev : found));
      } catch (err) {
        console.warn("update check failed", err);
      }
    }
    run();
    const id = setInterval(run, UPDATE_CHECK_INTERVAL_MS);
    return () => { alive = false; clearInterval(id); };
  }, []);

  // Agentic pen tests run outside the scan toasts, so listen for them too.
  useEffect(() => {
    const offs: Array<() => void> = [];
    let alive = true;
    const keep = (fn: () => void) => (alive ? offs.push(fn) : fn());
    listen("pentest-started", () => setPenTestRunning(true)).then(keep).catch(() => {});
    listen("pentest-ended", () => setPenTestRunning(false)).then(keep).catch(() => {});
    return () => { alive = false; offs.forEach((f) => f()); };
  }, []);

  const install = useCallback(async () => {
    if (!update || installing.current) return;
    installing.current = true;
    setProgress(0);
    let total = 0;
    let done = 0;
    try {
      await update.downloadAndInstall((ev) => {
        if (ev.event === "Started") total = ev.data.contentLength ?? 0;
        else if (ev.event === "Progress") {
          done += ev.data.chunkLength;
          if (total > 0) setProgress(Math.min(100, Math.round((done / total) * 100)));
        }
      });
      await relaunch();
    } catch (err) {
      console.warn("update install failed", err);
      installing.current = false;
      setProgress(null);
      setLater(true); // fail quietly; the next check will offer it again
    }
  }, [update]);

  if (!update || later || busy || penTestRunning) return null;

  const notes = update.body?.trim();
  return (
    <div className="upd-card" role="dialog" aria-label="Update available">
      <p className="upd-title">A new version of Trojan is ready (v{update.version}).</p>
      {notes && <p className="upd-notes">{notes}</p>}
      {progress === null ? (
        <div className="upd-actions">
          <button className="upd-btn upd-btn-primary" onClick={install}>Update now</button>
          <button className="upd-btn" onClick={() => setLater(true)}>Later</button>
        </div>
      ) : (
        <div role="progressbar" aria-valuenow={progress} aria-valuemin={0} aria-valuemax={100}>
          <span>Downloading… {progress}%</span>
          <div className="upd-bar"><div style={{ width: `${progress}%` }} /></div>
        </div>
      )}
    </div>
  );
}
