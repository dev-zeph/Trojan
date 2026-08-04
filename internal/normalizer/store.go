package normalizer

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// ScanResult wraps findings with metadata about the scan.
type ScanResult struct {
	Timestamp   time.Time      `json:"timestamp"`
	ProjectPath string         `json:"project_path"`
	Findings    []Finding      `json:"findings"`
	Packages    []Package      `json:"packages,omitempty"`
	Privacy     *PrivacyReport `json:"privacy,omitempty"`
}

// NewScanResult creates an in-memory ScanResult without writing anything to disk.
// Used for free-tier users — findings are served from memory only and discarded
// when the local server closes.
func NewScanResult(projectPath string, findings []Finding) *ScanResult {
	return &ScanResult{
		Timestamp:   time.Now(),
		ProjectPath: projectPath,
		Findings:    findings,
	}
}

// SaveScanResult writes scan results to <projectPath>/.trojan/scans/[timestamp].json
// and returns the ScanResult for use by the local server.
// Only called for Pro users — free users use NewScanResult instead.
func SaveScanResult(projectPath string, findings []Finding) (*ScanResult, error) {
	return SaveScanResultAt(projectPath, projectPath, findings)
}

// SaveScanResultAt writes scan results under <dir>/.trojan/scans/ while recording
// `projectPath` as the scan's display path. This splits the two for URL-targeted
// scans (DAST / agentic pen-tests): the file lands under the current working
// directory (so `trojan mcp`, run from the same project, can read it) while the
// ProjectPath shows the scanned URL. The MCP server reads the latest file in
// <cwd>/.trojan/scans/ (internal/mcpserver/server.go), so persisting here is what
// makes DAST findings available to MCP clients.
func SaveScanResultAt(dir, projectPath string, findings []Finding) (*ScanResult, error) {
	scansDir := filepath.Join(dir, ".trojan", "scans")
	if err := os.MkdirAll(scansDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create scans directory: %w", err)
	}

	result := &ScanResult{
		Timestamp:   time.Now(),
		ProjectPath: projectPath,
		Findings:    findings,
	}

	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to serialize findings: %w", err)
	}

	filename := fmt.Sprintf("%s.json", time.Now().Format("2006-01-02T15-04-05"))
	outputPath := filepath.Join(scansDir, filename)

	if err := os.WriteFile(outputPath, data, 0644); err != nil {
		return nil, fmt.Errorf("failed to write scan results: %w", err)
	}

	fmt.Printf("Results saved to %s\n", outputPath)
	return result, nil
}
