// Shared domain types for the desktop app.
// Extracted verbatim from App.tsx; no shape changes.

export type NavView  = "overview" | "sast" | "dast" | "market" | "dependencies" | "threatlab" | "licenses" | "privacy" | "compliancelab" | "history" | "autofix" | "profile" | "report";
export type ScanType = "sast" | "dast";

export interface PackageAdvisory { id: string; severity: string; summary: string; fix_version?: string; }
export interface PkgInfo { name: string; version: string; ecosystem: string; direct: boolean; cve_count: number; highest_severity?: string; fix_version?: string; advisories?: PackageAdvisory[]; license?: string; license_risk?: string; }
export interface PrivacyDataType { name: string; category: string; category_groups: string[]; detection_count: number; locations: { file: string; line: number; column_start: number; column_end: number }[]; }
export interface PrivacyThirdParty { name: string; data_types: string[]; risk_count: number; }
export interface PrivacyReport { data_types: PrivacyDataType[]; third_party: PrivacyThirdParty[]; }

export interface ComplianceLabResult {
  grade: "A" | "B" | "C" | "D" | "F";
  score: number;
  executive_summary: string;
  license_verdict: string;
  privacy_verdict: string;
  recommendations: string[];
}

export interface Finding { id: string; title: string; severity: string; scanner: string; file?: string; line?: number; description?: string; }
export interface ScanSummary { critical: number; high: number; medium: number; low: number; info: number; total: number; scannedAt: string; }

export interface AttackVector { title: string; severity: string; description: string; findings_involved: string[]; exploitability: "easy" | "moderate" | "hard"; }
export interface PriorityFix  { rank: number; type: "code" | "package" | "config"; title: string; description: string; command?: string; file?: string; line?: number; finding_id?: string; }

export interface ThreatLabResult {
  threat_index: number;
  grade: "A" | "B" | "C" | "D" | "F";
  verdict: string;
  attack_vectors: AttackVector[];
  priority_fixes: PriorityFix[];
  compliance_summary: string;
  key_risks: string[];
}

export interface AuthStatus { loggedIn: boolean; isPro: boolean; plan: string; email?: string; }

export interface RecentProject { path: string; name: string; type: ScanType; scannedAt: string; reportUrl?: string; cachePath?: string; }
export interface UserProfile   { name: string; email: string; token?: string; refreshToken?: string; familiarity?: number; aboutYou?: string; avatarDataUrl?: string; }

export interface Toast {
  id: string;
  label: string;
  type: ScanType;
  path: string;
  status: "scanning" | "done" | "error";
  reportUrl?: string;
  cachePath?: string;
  error?: string;
}
