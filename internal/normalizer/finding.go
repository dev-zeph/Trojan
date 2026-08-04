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

	// CWE and compliance fields
	CWEIDs     []string            `json:"cwe_ids,omitempty"`    // e.g. ["CWE-79", "CWE-89"]
	OWASP      []string            `json:"owasp,omitempty"`      // e.g. ["A03:2021 - Injection"]
	Compliance []ComplianceMapping `json:"compliance,omitempty"` // mapped from CWE IDs

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

	// Triage verdict — adversarial false-positive check (agentic DAST Phase 1),
	// populated for Pro users. See internal/ai/triage.go.
	Verdict           string  `json:"Verdict,omitempty"`           // "confirmed" | "likely_fp" | "needs_manual"
	VerdictReason     string  `json:"VerdictReason,omitempty"`     // one- or two-sentence rationale
	VerdictConfidence float64 `json:"VerdictConfidence,omitempty"` // 0..1

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

// LicenseRisk classifies how a license affects your project.
type LicenseRisk string

const (
	LicensePermissive    LicenseRisk = "permissive"     // MIT, BSD, Apache — do what you want
	LicenseWeakCopyleft  LicenseRisk = "weak-copyleft"  // LGPL, MPL — OK if not modified
	LicenseCopyleft      LicenseRisk = "copyleft"       // GPL, AGPL — may require open-sourcing
	LicenseUnknown       LicenseRisk = "unknown"        // no license declared — review needed
)

// Package represents a third-party dependency found during scanning.
// Populated by Trivy (vulnerabilities) and Syft (licenses).
type Package struct {
	Name            string            `json:"name"`
	Version         string            `json:"version"`
	Ecosystem       string            `json:"ecosystem"`        // "npm", "PyPI", "Go", etc.
	Direct          bool              `json:"direct"`           // false = transitive dependency
	CVECount        int               `json:"cve_count"`
	HighestSeverity Severity          `json:"highest_severity,omitempty"`
	FixVersion      string            `json:"fix_version,omitempty"` // earliest fix across all advisories
	Advisories      []PackageAdvisory `json:"advisories,omitempty"`
	License         string            `json:"license,omitempty"`      // SPDX identifier e.g. "MIT", "GPL-3.0"
	LicenseRisk     LicenseRisk       `json:"license_risk,omitempty"` // permissive, weak-copyleft, copyleft, unknown
}

// ComplianceMapping links a finding to a compliance framework control.
type ComplianceMapping struct {
	Framework string `json:"framework"` // "SOC 2", "PCI-DSS", "HIPAA", "OWASP"
	Control   string `json:"control"`   // e.g. "CC6.1", "6.5.1", "§164.312(a)"
	Title     string `json:"title"`     // human-readable control name
}

// PrivacyDataType represents a detected PII/sensitive data flow.
type PrivacyDataType struct {
	Name           string   `json:"name"`            // e.g. "Email Address", "Password"
	Category       string   `json:"category"`        // e.g. "Contact", "Authentication"
	CategoryGroups []string `json:"category_groups"` // e.g. ["PII", "Personal Data"]
	DetectionCount int      `json:"detection_count"`
	Locations      []struct {
		File       string `json:"file"`
		Line       int    `json:"line"`
		ColumnStart int   `json:"column_start"`
		ColumnEnd   int   `json:"column_end"`
	} `json:"locations"`
}

// PrivacyThirdParty represents a detected third-party service receiving data.
type PrivacyThirdParty struct {
	Name      string   `json:"name"`       // e.g. "Stripe", "Google Analytics"
	DataTypes []string `json:"data_types"` // what data flows to them
	RiskCount int      `json:"risk_count"` // total risk failures
}

// PrivacyReport holds all privacy data flow analysis results.
type PrivacyReport struct {
	DataTypes  []PrivacyDataType  `json:"data_types"`
	ThirdParty []PrivacyThirdParty `json:"third_party"`
}
