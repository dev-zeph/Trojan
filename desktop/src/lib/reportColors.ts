// Canonical grade/severity/license-risk color mapping, built on the
// semantic design tokens in App.css (--success/--warning/--destructive/etc).
// Previously this logic was copy-pasted independently 5 times across
// App.tsx and the Print*.tsx report generators, each with slightly
// different hex values (three different "C-grade" oranges existed at once).
// Every call site should import from here instead of redefining its own map.

export type Grade = "A" | "B" | "C" | "D" | "F";

const GRADE_COLORS: Record<Grade, string> = {
  A: "var(--success)",
  B: "var(--success)",
  C: "var(--warning)",
  D: "var(--warning)",
  F: "var(--destructive)",
};

export function gradeColor(grade: string | null | undefined): string {
  if (grade && grade in GRADE_COLORS) return GRADE_COLORS[grade as Grade];
  return "var(--muted-fg)";
}

export type Severity = "critical" | "high" | "medium" | "low" | "info" | "safe" | "unknown";

const SEVERITY_COLORS: Record<Severity, string> = {
  critical: "var(--destructive)",
  high: "var(--destructive)",
  medium: "var(--warning)",
  low: "var(--blue)",
  info: "var(--blue)",
  safe: "var(--success)",
  unknown: "var(--muted-fg)",
};

export function severityColor(sev: string | null | undefined): string {
  const key = (sev ?? "unknown").toLowerCase() as Severity;
  return SEVERITY_COLORS[key] ?? "var(--muted-fg)";
}

export type LicenseRisk = "copyleft" | "weak-copyleft" | "unknown" | "permissive";

const LICENSE_RISK_COLORS: Record<LicenseRisk, string> = {
  copyleft: "var(--destructive)",
  "weak-copyleft": "var(--warning)",
  unknown: "var(--muted-fg)",
  permissive: "var(--success)",
};

export function licenseRiskColor(risk: string | null | undefined): string {
  const key = (risk || "unknown") as LicenseRisk;
  return LICENSE_RISK_COLORS[key] ?? LICENSE_RISK_COLORS.unknown;
}
