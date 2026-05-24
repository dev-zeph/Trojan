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
	Timestamp time.Time `json:"timestamp"`
	ProjectPath string  `json:"project_path"`
	Findings  []Finding `json:"findings"`
}

// SaveScan writes scan results to .trojan/scans/[timestamp].json
// in the project directory.
func SaveScan(projectPath string, findings []Finding) (string, error) {
	// Create .trojan/scans/ directory if it doesn't exist
	scansDir := filepath.Join(projectPath, ".trojan", "scans")
	if err := os.MkdirAll(scansDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create scans directory: %w", err)
	}

	result := ScanResult{
		Timestamp:   time.Now(),
		ProjectPath: projectPath,
		Findings:    findings,
	}

	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to serialize findings: %w", err)
	}

	filename := fmt.Sprintf("%s.json", time.Now().Format("2006-01-02T15-04-05"))
	outputPath := filepath.Join(scansDir, filename)

	if err := os.WriteFile(outputPath, data, 0644); err != nil {
		return "", fmt.Errorf("failed to write scan results: %w", err)
	}

	return outputPath, nil
}
