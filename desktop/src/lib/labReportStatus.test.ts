import { describe, expect, it } from "vitest";
import {
  LAB_REPORT_DAILY_CAP,
  labReportName,
  labReportStatusMessage,
  type LabReportKind,
} from "./labReportStatus";

const kinds: LabReportKind[] = ["compliance", "security", "pen-test"];

describe("labReportStatusMessage", () => {
  it("maps 401 to a short sign-in sentence with the report name", () => {
    expect(labReportStatusMessage("compliance", 401)).toBe(
      "Sign in to generate a compliance report.",
    );
    expect(labReportStatusMessage("security", 401)).toBe(
      "Sign in to generate a security report.",
    );
    expect(labReportStatusMessage("pen-test", 401)).toBe(
      "Sign in to generate a pen-test report.",
    );
  });

  it("maps 402 to the same out-of-tokens sentence for every report", () => {
    const expected =
      "You're out of tokens. Your monthly tokens refill next month, or you can buy more.";
    for (const kind of kinds) {
      expect(labReportStatusMessage(kind, 402)).toBe(expected);
    }
  });

  it("maps 429 with each function's real daily cap", () => {
    expect(labReportStatusMessage("compliance", 429)).toBe(
      "You've reached today's limit of 20 compliance reports. Try again tomorrow.",
    );
    expect(labReportStatusMessage("security", 429)).toBe(
      "You've reached today's limit of 20 security reports. Try again tomorrow.",
    );
    expect(labReportStatusMessage("pen-test", 429)).toBe(
      "You've reached today's limit of 100 pen-test reports. Try again tomorrow.",
    );
  });

  it("leaves 429 unmapped when the function has no daily cap", () => {
    expect(labReportStatusMessage("compliance", 429, null)).toBeUndefined();
  });

  it("does not map 403 or other statuses", () => {
    for (const kind of kinds) {
      expect(labReportStatusMessage(kind, 403)).toBeUndefined();
      expect(labReportStatusMessage(kind, 500)).toBeUndefined();
      expect(labReportStatusMessage(kind, 200)).toBeUndefined();
    }
  });

  it("records the caps taken from the deployed functions", () => {
    expect(LAB_REPORT_DAILY_CAP).toEqual({
      compliance: 20,
      security: 20,
      "pen-test": 100,
    });
    expect(labReportName("pen-test")).toBe("pen-test report");
  });
});
