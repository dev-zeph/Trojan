export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info'
export type Status = 'open' | 'resolved' | 'suppressed'

export interface Finding {
  ID: string
  Scanner: string
  Category: string
  Severity: Severity
  Title: string
  RawMessage: string
  FilePath: string      // matched-at URL for DAST findings
  LineNumber: number
  CodeSnippet: string   // HTTP request snippet
  RuleID: string
  Status: Status
  Simply?: string
  Actions?: string[]
}

export interface ScanResult {
  timestamp: string
  project_path: string  // the scanned URL (e.g. http://localhost:3000)
  findings: Finding[]
  locked_count: number
}
