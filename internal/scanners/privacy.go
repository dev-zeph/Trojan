package scanners

import (
	"encoding/json"
	"os/exec"

	"github.com/dev-zeph/trojan/internal/normalizer"
)

// RunPrivacyScan runs Bearer in privacy + dataflow mode and returns a PrivacyReport.
// Requires Bearer to be installed. Returns nil if Bearer is unavailable.
func RunPrivacyScan(projectPath string) *normalizer.PrivacyReport {
	if !IsInstalled("bearer") {
		return nil
	}

	report := &normalizer.PrivacyReport{}

	// Run privacy report for subjects + third-party data flows.
	privacyArgs := []string{
		"scan", "--format", "json", "--quiet", "--report", "privacy",
		"--skip-path", "node_modules",
		"--skip-path", "vendor",
		"--skip-path", "dist",
		projectPath,
	}
	if out, err := exec.Command(ManagedBinary("bearer"), privacyArgs...).Output(); err == nil {
		var privResult bearerPrivacyOutput
		if json.Unmarshal(out, &privResult) == nil {
			for _, s := range privResult.Subjects {
				report.DataTypes = append(report.DataTypes, normalizer.PrivacyDataType{
					Name:           s.Name,
					Category:       s.SubjectName,
					CategoryGroups: []string{"PII", "Personal Data"},
					DetectionCount: s.DetectionCount,
				})
			}
			for _, tp := range privResult.ThirdParty {
				report.ThirdParty = append(report.ThirdParty, normalizer.PrivacyThirdParty{
					Name:      tp.ThirdParty,
					DataTypes: tp.DataTypes,
					RiskCount: tp.CriticalCount + tp.HighCount + tp.MediumCount + tp.LowCount,
				})
			}
		}
	}

	// Run dataflow report for file-level PII locations.
	dataflowArgs := []string{
		"scan", "--format", "json", "--quiet", "--report", "dataflow",
		"--skip-path", "node_modules",
		"--skip-path", "vendor",
		"--skip-path", "dist",
		projectPath,
	}
	if out, err := exec.Command(ManagedBinary("bearer"), dataflowArgs...).Output(); err == nil {
		var dfResult bearerDataflowOutput
		if json.Unmarshal(out, &dfResult) == nil {
			// Enrich DataTypes with file locations from the dataflow report.
			for i, dt := range report.DataTypes {
				for _, dfd := range dfResult.DataTypes {
					if dfd.Name == dt.Name {
						for _, det := range dfd.Detectors {
							for _, loc := range det.Locations {
								report.DataTypes[i].Locations = append(report.DataTypes[i].Locations, struct {
									File        string `json:"file"`
									Line        int    `json:"line"`
									ColumnStart int    `json:"column_start"`
									ColumnEnd   int    `json:"column_end"`
								}{
									File:        loc.Filename,
									Line:        loc.StartLineNumber,
									ColumnStart: loc.StartColumnNumber,
									ColumnEnd:   loc.EndColumnNumber,
								})
							}
						}
						break
					}
				}
			}
			// Add third-party components from dataflow.
			for _, comp := range dfResult.Components {
				found := false
				for _, existing := range report.ThirdParty {
					if existing.Name == comp.Name {
						found = true
						break
					}
				}
				if !found && comp.SubType == "third_party" {
					report.ThirdParty = append(report.ThirdParty, normalizer.PrivacyThirdParty{
						Name:      comp.Name,
						DataTypes: []string{},
					})
				}
			}
		}
	}

	if len(report.DataTypes) == 0 && len(report.ThirdParty) == 0 {
		return nil
	}
	return report
}

// Bearer privacy JSON shapes.
type bearerPrivacyOutput struct {
	Subjects []struct {
		SubjectName    string `json:"subject_name"`
		Name           string `json:"name"`
		DetectionCount int    `json:"detection_count"`
		CriticalCount  int    `json:"critical_risk_failure_count"`
		HighCount      int    `json:"high_risk_failure_count"`
		MediumCount    int    `json:"medium_risk_failure_count"`
		LowCount       int    `json:"low_risk_failure_count"`
	} `json:"subjects"`
	ThirdParty []struct {
		ThirdParty    string   `json:"third_party"`
		SubjectName   string   `json:"subject_name"`
		DataTypes     []string `json:"data_types"`
		CriticalCount int      `json:"critical_risk_failure_count"`
		HighCount     int      `json:"high_risk_failure_count"`
		MediumCount   int      `json:"medium_risk_failure_count"`
		LowCount      int      `json:"low_risk_failure_count"`
	} `json:"third_party"`
}

type bearerDataflowOutput struct {
	DataTypes []struct {
		Name      string `json:"name"`
		Detectors []struct {
			Name      string `json:"name"`
			Locations []struct {
				Filename          string `json:"filename"`
				StartLineNumber   int    `json:"start_line_number"`
				StartColumnNumber int    `json:"start_column_number"`
				EndColumnNumber   int    `json:"end_column_number"`
			} `json:"locations"`
		} `json:"detectors"`
	} `json:"data_types"`
	Components []struct {
		Name    string `json:"name"`
		Type    string `json:"type"`
		SubType string `json:"sub_type"`
	} `json:"components"`
}
