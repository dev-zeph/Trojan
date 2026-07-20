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
}
