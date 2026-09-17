import { describe, expect, it } from "vitest";
import {
  extractExternalLinkUrl,
  createExternalLinkListener,
  isIframeOffOrigin,
  restoreReport,
} from "./reportBridge";

const fakeIframeWindow = {} as Window;
const otherWindow = {} as Window;

describe("extractExternalLinkUrl", () => {
  it("extracts the url from a well-formed message sent by our iframe", () => {
    const url = extractExternalLinkUrl(
      { source: fakeIframeWindow, data: { source: "trojan-report", type: "open-external", url: "https://trojancli.com/pricing" } },
      fakeIframeWindow,
    );
    expect(url).toBe("https://trojancli.com/pricing");
  });

  it("ignores messages that did not come from our iframe's window", () => {
    const url = extractExternalLinkUrl(
      { source: otherWindow, data: { source: "trojan-report", type: "open-external", url: "https://evil.example/x" } },
      fakeIframeWindow,
    );
    expect(url).toBeNull();
  });

  it("ignores messages with the wrong shape", () => {
    expect(extractExternalLinkUrl({ source: fakeIframeWindow, data: null }, fakeIframeWindow)).toBeNull();
    expect(extractExternalLinkUrl({ source: fakeIframeWindow, data: { source: "other", type: "open-external", url: "x" } }, fakeIframeWindow)).toBeNull();
    expect(extractExternalLinkUrl({ source: fakeIframeWindow, data: { source: "trojan-report", type: "not-it", url: "x" } }, fakeIframeWindow)).toBeNull();
  });

  it("returns null when there is no iframe window yet", () => {
    expect(
      extractExternalLinkUrl({ source: fakeIframeWindow, data: { source: "trojan-report", type: "open-external", url: "x" } }, null),
    ).toBeNull();
  });
});

describe("createExternalLinkListener", () => {
  it("does NOT navigate the iframe and DOES call the opener for a valid external-link message", () => {
    const opened: string[] = [];
    const listener = createExternalLinkListener(() => fakeIframeWindow, (url) => opened.push(url));

    listener({ source: fakeIframeWindow, data: { source: "trojan-report", type: "open-external", url: "https://trojancli.com/pricing" } });

    expect(opened).toEqual(["https://trojancli.com/pricing"]);
  });

  it("does not call the opener for messages from other windows", () => {
    const opened: string[] = [];
    const listener = createExternalLinkListener(() => fakeIframeWindow, (url) => opened.push(url));

    listener({ source: otherWindow, data: { source: "trojan-report", type: "open-external", url: "https://evil.example" } });

    expect(opened).toEqual([]);
  });
});

describe("isIframeOffOrigin", () => {
  it("is false when the iframe is still on the report's own origin", () => {
    const result = isIframeOffOrigin("http://127.0.0.1:5173/report", () => "http://127.0.0.1:5173/report/findings");
    expect(result).toBe(false);
  });

  it("is true once the iframe navigated to a different origin", () => {
    const result = isIframeOffOrigin("http://127.0.0.1:5173/report", () => "https://trojancli.com/pricing");
    expect(result).toBe(true);
  });

  it("is true when reading the href throws (genuinely cross-origin frame)", () => {
    const result = isIframeOffOrigin("http://127.0.0.1:5173/report", () => {
      throw new Error("SecurityError: cross-origin");
    });
    expect(result).toBe(true);
  });

  it("is false when there is no report loaded yet", () => {
    expect(isIframeOffOrigin("", () => "https://trojancli.com/pricing")).toBe(false);
  });
});

describe("restoreReport", () => {
  it("restores the frame's src to the report URL", () => {
    const frame = { src: "https://trojancli.com/pricing" };
    restoreReport(frame, "http://127.0.0.1:5173/report");
    expect(frame.src).toBe("http://127.0.0.1:5173/report");
  });

  it("does nothing without a frame or a report URL", () => {
    expect(() => restoreReport(null, "http://127.0.0.1:5173/report")).not.toThrow();
    const frame = { src: "https://trojancli.com/pricing" };
    restoreReport(frame, "");
    expect(frame.src).toBe("https://trojancli.com/pricing");
  });
});
