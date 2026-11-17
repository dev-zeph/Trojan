export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info'
export type Status = 'open' | 'resolved' | 'suppressed'

export interface Finding {
  ID: string
  Scanner: string
  Category: string
  Severity: Severity
  Title: string
  RawMessage: string
  FilePath: string
  LineNumber: number
  CodeSnippet: string
  RuleID: string
  Status: Status
  Simply?: string
  Actions?: string[]
  locked?: boolean
  // Trojan's AI false-alarm check. "likely_fp" findings are hidden from the
  // list and the counts, behind the "Trojan hid N false alarms" disclosure.
  Verdict?: 'confirmed' | 'likely_fp' | 'needs_manual'
  VerdictReason?: string
  VerdictConfidence?: number
}

export interface PackageAdvisory {
  id: string
  severity: Severity
  summary: string
  fix_version?: string
}

export interface Package {
  name: string
  version: string
  ecosystem: string
  direct: boolean
  cve_count: number
  highest_severity?: Severity
  fix_version?: string
  advisories?: PackageAdvisory[]
}

export interface ScanResult {
  timestamp: string
  project_path: string
  findings: Finding[]
  locked_count: number
  packages?: Package[]
  // Set when the project has source in a language the code-graph checks don't
  // parse (e.g. PHP): those files were covered by the rule scanners instead.
  coverage_note?: string
  // Set when the false-alarm check couldn't finish; everything is shown.
  triage_note?: string
}
