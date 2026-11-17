import { describe, expect, it, vi } from "vitest";
import { render, screen, act, waitFor } from "@testing-library/react";

type Handler = (e: { payload: unknown }) => void;
const handlers: Record<string, Handler> = {};
vi.mock("@tauri-apps/api/event", () => ({
  listen: (name: string, cb: Handler) => {
    handlers[name] = cb;
    return Promise.resolve(() => { delete handlers[name]; });
  },
}));

import { ScanProgress, progressHeading, useScanProgress } from "./ScanProgress";

const FALLBACK = "Running SAST · SCA · Secrets · IaC";

describe("ScanProgress", () => {
  it("renders the fallback exactly when there is no progress", () => {
    render(<ScanProgress progress={null} fallback={<p>{FALLBACK}</p>} />);
    expect(screen.getByText(FALLBACK)).toBeTruthy();
    expect(screen.queryByTestId("scan-progress")).toBeNull();
  });

  it("shows step text, label and a bar that fills by steps", () => {
    render(
      <ScanProgress
        progress={{ step: 3, total: 6, key: "gitleaks", label: "Checking for leaked passwords and keys" }}
        fallback={<p>{FALLBACK}</p>}
      />,
    );
    expect(screen.getByText("Step 3 of 6")).toBeTruthy();
    expect(screen.getByText("Checking for leaked passwords and keys")).toBeTruthy();
    expect(screen.queryByText(FALLBACK)).toBeNull();
    const bar = screen.getByRole("progressbar");
    expect(bar.getAttribute("aria-valuenow")).toBe("3");
    expect(bar.getAttribute("aria-valuemax")).toBe("6");
    expect((bar.firstChild as HTMLElement).style.width).toBe("50%");
  });

  it("open-ended phase shows a running count and no bar", () => {
    render(
      <ScanProgress
        progress={{ step: 0, total: 0, label: "Testing your site", count: 14, unit: "checks" }}
        fallback={null}
      />,
    );
    expect(screen.getByText("Ran 14 checks so far")).toBeTruthy();
    expect(screen.queryByRole("progressbar")).toBeNull();
  });

  it("heading helper", () => {
    expect(progressHeading({ step: 1, total: 2, label: "a" })).toBe("Step 1 of 2");
    expect(progressHeading({ step: 0, total: 0, label: "a" })).toBeNull();
    expect(progressHeading({ step: 0, total: 0, label: "a", count: 1, unit: "checks" })).toBe("Ran 1 check so far");
  });
});

function Probe({ active }: { active: boolean }) {
  const p = useScanProgress(active);
  return <ScanProgress progress={p} fallback={<p>fallback</p>} />;
}

describe("useScanProgress", () => {
  it("starts on fallback, follows events, ignores bad payloads, resets when inactive", async () => {
    const { rerender } = render(<Probe active />);
    expect(screen.getByText("fallback")).toBeTruthy();
    await waitFor(() => expect(handlers["scan-progress"]).toBeTruthy());

    act(() => handlers["scan-progress"]({ payload: { oops: true } }));
    act(() => handlers["scan-progress"]({ payload: null }));
    expect(screen.getByText("fallback")).toBeTruthy();

    act(() => handlers["scan-progress"]({ payload: { step: 2, total: 5, key: "k", label: "Doing things" } }));
    expect(screen.getByText("Step 2 of 5")).toBeTruthy();

    rerender(<Probe active={false} />);
    expect(screen.getByText("fallback")).toBeTruthy();
  });
});
