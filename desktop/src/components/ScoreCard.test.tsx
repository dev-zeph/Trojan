import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { ScoreCard, ScoreNotes } from "./ScoreCard";
import { ReportDownloads } from "./ReportDownloads";
import { FounderHome } from "./FounderHome";
import type { ScoreChange, ScoreEntry } from "../lib/scoreHistory";

afterEach(cleanup);

const entry: ScoreEntry = { score: 74, grade: "B", at: "2026-11-02T10:00:00Z", scanAt: "2026-11-02T09:59:00Z" };
const up: ScoreChange = { kind: "up", was: 58, now: 74, diff: 16 };

function card(over: Partial<Parameters<typeof ScoreCard>[0]> = {}) {
  const props = {
    projectName: "shop", entry, change: up, stale: false, hasReport: true, signedIn: true, running: false, scanReady: true,
    onUpdate: vi.fn(), onSignIn: vi.fn(), onDownloadTxt: vi.fn(), onDownloadPdf: vi.fn(), onOpenReport: vi.fn(),
    ...over,
  };
  render(<ScoreCard {...props} />);
  return props;
}

describe("simple Home score card", () => {
  it("shows the score, grade and 'Was 58, now 74'", () => {
    card();
    expect(screen.getByTestId("score-value").textContent).toBe("74");
    expect(screen.getByText("B")).toBeInTheDocument();
    expect(screen.getByText("Was 58, now 74")).toBeInTheDocument();
  });

  it("offers PDF and TXT downloads that call through", () => {
    const p = card();
    fireEvent.click(screen.getByText("Download PDF"));
    fireEvent.click(screen.getByText("Download TXT"));
    expect(p.onDownloadPdf).toHaveBeenCalled();
    expect(p.onDownloadTxt).toHaveBeenCalled();
  });

  it("after a rescan it says the score is out of date and invites an update", () => {
    const p = card({ stale: true });
    expect(screen.getByTestId("score-stale").textContent).toMatch(/scanned again/);
    fireEvent.click(screen.getByText("Update your score"));
    expect(p.onUpdate).toHaveBeenCalled();
  });

  it("has no stale notice when the score is current", () => {
    card();
    expect(screen.queryByTestId("score-stale")).toBeNull();
  });

  it("invites a first score when there is a scan but no score yet", () => {
    card({ entry: null, change: null, hasReport: false });
    expect(screen.getByText("Get your score")).toBeInTheDocument();
    expect(screen.queryByText("Download PDF")).toBeNull();
  });

  it("asks a signed-out user to sign in", () => {
    const p = card({ signedIn: false });
    fireEvent.click(screen.getByText("Sign in to get your score"));
    expect(p.onSignIn).toHaveBeenCalled();
  });

  it("renders inside the founder Home", () => {
    render(
      <FounderHome
        name="Zeph" recent={[]} isScanning={false} mcpStatus={{}}
        onScanCode={() => {}} onTestWebsite={() => {}} onConnectAI={() => {}} onOpenRecent={() => {}}
        scoreCard={<ScoreCard projectName="shop" entry={entry} change={up} stale={false} hasReport signedIn running={false} scanReady
          onUpdate={() => {}} onSignIn={() => {}} onDownloadTxt={() => {}} onDownloadPdf={() => {}} onOpenReport={() => {}} />}
      />,
    );
    expect(screen.getByTestId("score-card")).toBeInTheDocument();
    expect(screen.getByText("Download PDF")).toBeInTheDocument();
  });
});

describe("report view notes and downloads (shared by both dashboards)", () => {
  it("ScoreNotes shows the change and the stale nudge", () => {
    const onUpdate = vi.fn();
    render(<ScoreNotes change={up} stale canUpdate running={false} onUpdate={onUpdate} />);
    expect(screen.getByTestId("score-change").textContent).toBe("Was 58, now 74");
    fireEvent.click(screen.getByText("Update your score"));
    expect(onUpdate).toHaveBeenCalled();
  });

  it("ReportDownloads has both buttons", () => {
    const onTxt = vi.fn(), onPdf = vi.fn();
    render(<ReportDownloads onTxt={onTxt} onPdf={onPdf} />);
    fireEvent.click(screen.getByText("Export TXT"));
    fireEvent.click(screen.getByText("Export PDF"));
    expect(onTxt).toHaveBeenCalled();
    expect(onPdf).toHaveBeenCalled();
  });
});
