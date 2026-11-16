import type { ThreatLabResult } from "../types";
import { scoreFromResult } from "./scoreHistory";

// Plain-text version of the Security Report, shared by both dashboards.
export function buildReportTxt(r: ThreatLabResult): string {
  const lines = [
    "TROJAN SECURITY REPORT",
    "======================",
    "",
    `Security Score: ${scoreFromResult(r)}/100  |  Grade: ${r.grade}`,
    "",
    "VERDICT",
    r.verdict,
    "",
    "KEY RISKS",
    ...r.key_risks.map((risk) => `  • ${risk}`),
    "",
    "ATTACK VECTORS",
    ...r.attack_vectors.map((v) => [
      `  [${v.severity.toUpperCase()}] ${v.title}  (exploitability: ${v.exploitability})`,
      `  ${v.description}`,
      `  Involves: ${v.findings_involved.join(", ")}`,
      "",
    ].join("\n")),
    "PRIORITY FIXES",
    ...r.priority_fixes.map((f) => [
      `  ${f.rank}. [${f.type.toUpperCase()}] ${f.title}`,
      `     ${f.description}`,
      f.command ? `     Command: ${f.command}` : "",
      f.file ? `     File: ${f.file}${f.line ? `:${f.line}` : ""}` : "",
      "",
    ].filter(Boolean).join("\n")),
    "COMPLIANCE",
    r.compliance_summary,
  ];
  return lines.join("\n");
}

export function downloadReportTxt(r: ThreatLabResult): void {
  const blob = new Blob([buildReportTxt(r)], { type: "text/plain" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = "trojan-security-report.txt";
  a.click();
  URL.revokeObjectURL(a.href);
}

// PDF goes through the existing print flow (the print portal renders the report).
export function printReportPdf(projectName: string): void {
  const t = document.title;
  document.title = `Security Assessment - ${projectName || "Report"}`;
  window.print();
  document.title = t;
}
