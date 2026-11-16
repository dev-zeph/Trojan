import { describe, expect, it, vi, beforeEach } from "vitest";
import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";

const checkMock = vi.fn();
const relaunchMock = vi.fn();
vi.mock("@tauri-apps/plugin-updater", () => ({ check: (...a: unknown[]) => checkMock(...a) }));
vi.mock("@tauri-apps/plugin-process", () => ({ relaunch: () => relaunchMock() }));
vi.mock("@tauri-apps/api/event", () => ({ listen: () => Promise.resolve(() => {}) }));

import { UpdatePrompt } from "./UpdatePrompt";

const fake = (over = {}) => ({
  version: "0.5.0",
  body: "Faster scans",
  downloadAndInstall: vi.fn().mockResolvedValue(undefined),
  ...over,
});

describe("UpdatePrompt", () => {
  beforeEach(() => { checkMock.mockReset(); relaunchMock.mockReset(); });

  it("shows when an update is available", async () => {
    checkMock.mockResolvedValue(fake());
    render(<UpdatePrompt busy={false} />);
    expect(await screen.findByText("A new version of Trojan is ready (v0.5.0).")).toBeTruthy();
    expect(screen.getByText("Faster scans")).toBeTruthy();
  });

  it("is hidden when there is no update", async () => {
    checkMock.mockResolvedValue(null);
    render(<UpdatePrompt busy={false} />);
    await waitFor(() => expect(checkMock).toHaveBeenCalled());
    expect(screen.queryByText(/new version of Trojan/)).toBeNull();
  });

  it("is hidden when the check fails", async () => {
    checkMock.mockRejectedValue(new Error("offline"));
    render(<UpdatePrompt busy={false} />);
    await waitFor(() => expect(checkMock).toHaveBeenCalled());
    expect(screen.queryByText(/new version of Trojan/)).toBeNull();
  });

  it("waits while a scan runs, then shows", async () => {
    checkMock.mockResolvedValue(fake());
    const { rerender } = render(<UpdatePrompt busy={true} />);
    await waitFor(() => expect(checkMock).toHaveBeenCalled());
    expect(screen.queryByText(/new version of Trojan/)).toBeNull();
    rerender(<UpdatePrompt busy={false} />);
    expect(await screen.findByText(/new version of Trojan/)).toBeTruthy();
  });

  it("Later hides it", async () => {
    checkMock.mockResolvedValue(fake());
    render(<UpdatePrompt busy={false} />);
    fireEvent.click(await screen.findByText("Later"));
    expect(screen.queryByText(/new version of Trojan/)).toBeNull();
  });

  it("Update now installs and relaunches", async () => {
    const u = fake();
    checkMock.mockResolvedValue(u);
    render(<UpdatePrompt busy={false} />);
    const btn = await screen.findByText("Update now");
    await act(async () => { fireEvent.click(btn); });
    expect(u.downloadAndInstall).toHaveBeenCalled();
    expect(relaunchMock).toHaveBeenCalled();
  });
});
