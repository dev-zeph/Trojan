/** Report kinds that call a token-metered Supabase edge function. */
export type LabReportKind = "compliance" | "security" | "pen-test";

/**
 * Daily caps taken from the deployed edge functions (DAILY_LIMIT).
 * Omit a kind here if that function has no cap, so 429 is left unmapped.
 */
export const LAB_REPORT_DAILY_CAP: Partial<Record<LabReportKind, number>> = {
  compliance: 20,
  security: 20,
  "pen-test": 100,
};

export function labReportName(kind: LabReportKind): string {
  if (kind === "compliance") return "compliance report";
  if (kind === "security") return "security report";
  return "pen-test report";
}

/**
 * Map an edge-function HTTP status to the user-facing string for this report.
 * Returns undefined when this status has no dedicated copy (including 429
 * when the function has no daily cap), so the caller can fall through.
 */
export function labReportStatusMessage(
  kind: LabReportKind,
  status: number,
  dailyCap: number | null | undefined = LAB_REPORT_DAILY_CAP[kind],
): string | undefined {
  const name = labReportName(kind);
  if (status === 401) return `Sign in to generate a ${name}.`;
  if (status === 402) {
    return "You're out of tokens. Your monthly tokens refill next month, or you can buy more.";
  }
  if (status === 429 && dailyCap != null) {
    return `You've reached today's limit of ${dailyCap} ${name}s. Try again tomorrow.`;
  }
  return undefined;
}
