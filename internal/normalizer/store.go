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
	Timestamp   time.Time `json:"timestamp"`
	ProjectPath string    `json:"project_path"`
	Findings    []Finding `json:"findings"`
}

// SaveScanResult writes scan results to .trojan/scans/[timestamp].json
// and returns the ScanResult for use by the local server.
func SaveScanResult(projectPath string, findings []Finding) (*ScanResult, error) {
	scansDir := filepath.Join(projectPath, ".trojan", "scans")
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
