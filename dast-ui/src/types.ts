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
  url?: string          // probed URL (same as FilePath for website findings)
  source_file?: string  // grey-box: project file of the handler, when known
  source_line?: number  // grey-box: line in source_file, 0/absent if unknown
  CodeSnippet: string   // HTTP request snippet
  RuleID: string
  Status: Status
  Simply?: string
  Actions?: string[]
  Verdict?: 'confirmed' | 'likely_fp' | 'needs_manual'
  VerdictReason?: string
  VerdictConfidence?: number
}

export interface ScanResult {
  timestamp: string
  project_path: string  // the scanned URL (e.g. http://localhost:3000)
  findings: Finding[]
  locked_count: number
}
