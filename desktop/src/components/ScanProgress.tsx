import { useEffect, useState, type ReactNode } from "react";
import { listen } from "@tauri-apps/api/event";
import "./ScanProgress.css";

/** Payload of the `scan-progress` event (see src-tauri/src/progress.rs).
 *  total 0 means an open-ended phase (the pen test): show the label and, if
 *  present, a running count. There is no percentage and no time estimate. */
export interface ScanProgressEvent {
  step: number;
  total: number;
  key?: string;
  label: string;
  count?: number;
  unit?: string;
}

/** Plain-words heading line: "Step 3 of 6" or "Ran 14 checks so far". */
export function progressHeading(p: ScanProgressEvent): string | null {
  if (p.total > 0) return `Step ${p.step} of ${p.total}`;
  if (typeof p.count === "number" && p.count > 0) {
    const unit = p.unit ?? "checks";
    const noun = p.count === 1 && unit.endsWith("s") ? unit.slice(0, -1) : unit;
    return `Ran ${p.count} ${noun} so far`;
  }
  return null;
}

/** Follows `scan-progress` events while a scan is running. Returns null until
 *  the first event arrives, and resets whenever `active` changes. */
export function useScanProgress(active: boolean): ScanProgressEvent | null {
  const [progress, setProgress] = useState<ScanProgressEvent | null>(null);

  useEffect(() => { setProgress(null); }, [active]);

  useEffect(() => {
    if (!active) return;
    let unlisten: (() => void) | undefined;
    let cancelled = false;
    listen<ScanProgressEvent>("scan-progress", (e) => {
      const p = e.payload;
      if (p && typeof p.label === "string" && p.label) setProgress(p);
    }).then((fn) => {
      if (cancelled) fn(); else unlisten = fn;
    });
    return () => { cancelled = true; unlisten?.(); };
  }, [active]);

  return progress;
}

interface Props {
  progress: ScanProgressEvent | null;
  /** Rendered exactly as before when no progress event has arrived. */
  fallback: ReactNode;
}

/** Step indicator: "Step 3 of 6", the label, and a thin bar that fills by
 *  steps. Falls back to `fallback` when there is no progress yet. */
export function ScanProgress({ progress, fallback }: Props) {
  if (!progress) return <>{fallback}</>;
  const heading = progressHeading(progress);
  const stepped = progress.total > 0;
  return (
    <div className="scan-progress" data-testid="scan-progress">
      {heading && <span className="scan-progress-step">{heading}</span>}
      <span className="scan-progress-label">{progress.label}</span>
      {stepped && (
        <span
          className="scan-progress-bar"
          role="progressbar"
          aria-valuemin={0}
          aria-valuemax={progress.total}
          aria-valuenow={progress.step}
          aria-label={`Step ${progress.step} of ${progress.total}`}
        >
          <span
            className="scan-progress-fill"
            style={{ width: `${Math.min(100, Math.round((progress.step / progress.total) * 100))}%` }}
          />
        </span>
      )}
    </div>
  );
}
