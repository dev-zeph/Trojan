import { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { loadRecent } from "./lib/store";

const DAY_MS = 24 * 60 * 60 * 1000;

/** Ask the app to nudge for any project that has not been scanned in a while.
 *  The Rust side decides who is due and keeps the once-a-week throttle. */
export async function runNudgeCheck() {
  try {
    const recents = await loadRecent();
    const projects = recents
      .map((r) => ({ path: r.path, name: r.name, last_scan: Math.floor(new Date(r.scannedAt).getTime() / 1000) }))
      .filter((p) => Number.isFinite(p.last_scan));
    if (projects.length) await invoke("nudge_check", { projects });
  } catch {
    // Not running inside the desktop app, or notifications are blocked. Stay quiet.
  }
}

/** Checks on app start and then once a day while the app is open. */
export function useScanNudges() {
  useEffect(() => {
    void runNudgeCheck();
    const id = setInterval(() => void runNudgeCheck(), DAY_MS);
    return () => clearInterval(id);
  }, []);
}

/** On/off toggle for scan reminders. Also runs the daily check while mounted. */
export default function NotificationSettings() {
  const [enabled, setEnabled] = useState(true);
  useScanNudges();

  useEffect(() => {
    invoke<boolean>("get_nudge_enabled").then(setEnabled).catch(() => {});
  }, []);

  const toggle = (next: boolean) => {
    setEnabled(next);
    invoke("set_nudge_enabled", { enabled: next }).catch(() => {});
  };

  return (
    <label style={{ display: "flex", alignItems: "center", gap: 10, cursor: "pointer" }}>
      <input type="checkbox" checked={enabled} onChange={(e) => toggle(e.target.checked)} />
      <span>
        Remind me to scan
        <span style={{ display: "block", opacity: 0.6, fontSize: "0.85em" }}>
          Get a gentle nudge when a project has gone a week without a scan.
        </span>
      </span>
    </label>
  );
}
