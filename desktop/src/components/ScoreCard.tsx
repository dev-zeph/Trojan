import { gradeColor } from "../lib/reportColors";
import { changeText, type ScoreChange, type ScoreEntry } from "../lib/scoreHistory";

// ── Security Score pieces shared by both dashboards ───────────────────────
// ScoreNotes: the "Was 58, now 74" line and the "scanned again" nudge, used in
// the Security Report view. ScoreCard: the simple Home score card.

export function ScoreNotes({ change, stale, canUpdate, running, onUpdate }: {
  change: ScoreChange | null;
  stale: boolean;
  canUpdate: boolean;
  running: boolean;
  onUpdate: () => void;
}) {
  const text = changeText(change);
  const dir = change && (change.kind === "up" || change.kind === "down") ? change.kind : "same";
  return (
    <>
      {text && <p className={`score-change score-change-${dir}`} data-testid="score-change">{text}</p>}
      {stale && (
        <div className="score-stale" data-testid="score-stale">
          <span>You scanned again since this score. It may be out of date.</span>
          {canUpdate && (
            <button className="score-stale-btn" onClick={onUpdate} disabled={running}>
              {running ? "Updating…" : "Update your score"}
            </button>
          )}
        </div>
      )}
    </>
  );
}

export function ScoreCard({
  projectName, entry, change, stale, hasReport, signedIn, running, scanReady,
  onUpdate, onSignIn, onDownloadTxt, onDownloadPdf, onOpenReport,
}: {
  projectName: string;
  entry: ScoreEntry | null;
  change: ScoreChange | null;
  stale: boolean;
  hasReport: boolean;
  signedIn: boolean;
  running: boolean;
  scanReady: boolean;          // a finished code scan exists to build a score from
  onUpdate: () => void;        // generate or regenerate
  onSignIn: () => void;
  onDownloadTxt: () => void;
  onDownloadPdf: () => void;
  onOpenReport: () => void;
}) {
  if (!scanReady && !entry) return null;
  const color = gradeColor(entry?.grade);
  const primaryLabel = running ? "Working…" : entry ? "Update your score" : "Get your score";

  return (
    <div className="fh-score" data-testid="score-card">
      <span className="fh-section-label">YOUR SECURITY SCORE{projectName ? `: ${projectName.toUpperCase()}` : ""}</span>
      {entry ? (
        <div className="fh-score-body">
          <div className="fh-score-num" style={{ color }}>
            <span data-testid="score-value">{entry.score}</span><span className="fh-score-denom">/100</span>
          </div>
          <div className="fh-score-grade" style={{ borderColor: color, color }}>{entry.grade}</div>
          <div className="fh-score-meta">
            <ScoreNotes change={change} stale={false} canUpdate={false} running={false} onUpdate={onUpdate} />
            <p className="fh-score-hint">Fix what Trojan found, scan again, then update your score to see it go up. An update costs 100 tokens.</p>
          </div>
        </div>
      ) : (
        <p className="fh-score-hint">Get a score from 0 to 100 for this project. Fix issues, scan again, and watch it improve.</p>
      )}

      {stale && entry && (
        <div className="score-stale" data-testid="score-stale">
          <span>You scanned again since this score. It may be out of date.</span>
        </div>
      )}

      <div className="fh-score-actions">
        {signedIn ? (
          <button className="fh-score-btn fh-score-btn-primary" onClick={onUpdate} disabled={running || !scanReady}>{primaryLabel}</button>
        ) : (
          <button className="fh-score-btn fh-score-btn-primary" onClick={onSignIn}>Sign in to get your score</button>
        )}
        {hasReport && (
          <>
            <button className="fh-score-btn" onClick={onDownloadPdf}>Download PDF</button>
            <button className="fh-score-btn" onClick={onDownloadTxt}>Download TXT</button>
            <button className="fh-score-btn" onClick={onOpenReport}>See full report</button>
          </>
        )}
      </div>
    </div>
  );
}
