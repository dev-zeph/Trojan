import { describe, expect, it, vi } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { GettingStarted, answersFor } from "./GettingStarted";
import { isLocalUrl } from "../lib/format";

describe("answersFor", () => {
  it("puts anyone not comfortable with security on the simple dashboard", () => {
    expect(answersFor("none", "ai-builder")).toMatchObject({ dashboard: "simple", familiarity: 0 });
    expect(answersFor("some", "ai-editor")).toMatchObject({ dashboard: "simple", familiarity: 1 });
    expect(answersFor("comfortable", "me")).toMatchObject({ dashboard: "full", familiarity: 2 });
  });

  it("describes who writes the code for the AI features", () => {
    expect(answersFor("none", "ai-builder").aboutYou).toMatch(/AI app builder/);
  });
});

describe("GettingStarted", () => {
  it("walks intro → two questions → setup and reports the answers", async () => {
    const onDone = vi.fn();
    render(<GettingStarted onDone={onDone} />);

    expect(screen.getByText("GETTING STARTED")).toBeTruthy();
    fireEvent.click(screen.getByText(/Let's begin/));
    fireEvent.click(await screen.findByText("None yet"));
    fireEvent.click(await screen.findByText("An AI app builder"));

    expect(await screen.findByText("Setting up your workspace")).toBeTruthy();
    await waitFor(() => expect(onDone).toHaveBeenCalledTimes(1), { timeout: 4000 });
    expect(onDone.mock.calls[0][0]).toMatchObject({
      securityExperience: "none",
      codeAuthor: "ai-builder",
      dashboard: "simple",
    });
  });
});

describe("isLocalUrl", () => {
  it.each([
    ["http://localhost:3000", true],
    ["http://127.0.0.1:8080/app", true],
    ["http://192.168.1.20", true],
    ["http://172.20.0.5", true],
    ["http://myapp.local", true],
    ["http://[::1]:3000", true],
    ["https://myapp.com", false],
    ["https://172.32.0.1", false],
    ["not a url", false],
  ])("%s → %s", (url, want) => {
    expect(isLocalUrl(url)).toBe(want);
  });
});
