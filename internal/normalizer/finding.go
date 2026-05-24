package normalizer

// Severity represents how critical a finding is.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// Status represents the current state of a finding.
type Status string

const (
	StatusOpen       Status = "open"
	StatusResolved   Status = "resolved"
	StatusSuppressed Status = "suppressed"
)

// Finding is the normalized representation of a security issue,
// regardless of which scanner produced it.
type Finding struct {
	ID          string   // Unique ID for this finding
	Scanner     string   // Which scanner found it (semgrep, trivy, gitleaks, etc.)
	Category    string   // Type of issue (sast, sca, secrets, iac)
	Severity    Severity // critical, high, medium, low, info
	Title       string   // Short human-readable title
	RawMessage  string   // Original message from the scanner
	FilePath    string   // Path to the affected file
	LineNumber  int      // Line number of the issue
	CodeSnippet string   // The affected code
	RuleID      string   // The scanner rule that triggered this
	Status      Status   // open, resolved, suppressed
}
