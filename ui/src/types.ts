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
}

export interface ScanResult {
  timestamp: string
  project_path: string
  findings: Finding[]
}
