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

	// Context fields — populated before AI synthesis
	Language        string // "typescript", "go", "python", "hcl", etc. (from file extension)
	Framework       string // "nextjs", "express", "gin", "fastapi", etc. (from project files)
	ProjectType     string // "nextjs", "go-api", "python-api", "static", etc.
	SurroundingCode string // 15 lines before + after LineNumber; empty for DAST/SCA findings

	// AI synthesis fields — populated for Pro users
	Simply          string   `json:"Simply,omitempty"`          // Plain-English explanation
	Actions         []string `json:"Actions,omitempty"`         // Step-by-step fix instructions
	Confidence      int      `json:"Confidence,omitempty"`      // 0-100 how sure the AI is this is real
	IsFalsePositive bool     `json:"IsFalsePositive,omitempty"` // true if AI thinks this is a false positive
	FixDiff         string   `json:"FixDiff,omitempty"`         // Optional git-style diff for the fix

	// Locked is set at serve time (never persisted to disk).
	// True when the finding is not accessible on the free plan.
	Locked bool `json:"locked,omitempty"`
}

// PackageAdvisory is a single security advisory attached to a dependency.
type PackageAdvisory struct {
	ID         string   `json:"id"`                    // CVE or GHSA identifier
	Severity   Severity `json:"severity"`
	Summary    string   `json:"summary"`
	FixVersion string   `json:"fix_version,omitempty"` // version that resolves this advisory
}

// Package represents a third-party dependency found during scanning.
// Populated by Trivy and attached to ScanResult.Packages.
type Package struct {
	Name            string            `json:"name"`
	Version         string            `json:"version"`
	Ecosystem       string            `json:"ecosystem"`        // "npm", "PyPI", "Go", etc.
	Direct          bool              `json:"direct"`           // false = transitive dependency
	CVECount        int               `json:"cve_count"`
	HighestSeverity Severity          `json:"highest_severity,omitempty"`
	FixVersion      string            `json:"fix_version,omitempty"` // earliest fix across all advisories
	Advisories      []PackageAdvisory `json:"advisories,omitempty"`
}
