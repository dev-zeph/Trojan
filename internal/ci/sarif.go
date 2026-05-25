package ci

import (
	"encoding/json"

	"github.com/dev-zeph/trojan/internal/normalizer"
)

// SARIF 2.1.0 structures

type sarifRoot struct {
	Schema  string    `json:"$schema"`
	Version string    `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name    string      `json:"name"`
	Version string      `json:"version"`
	Rules   []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string          `json:"id"`
	Name             string          `json:"name"`
	ShortDescription sarifMessageText `json:"shortDescription"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   sarifMessageText `json:"message"`
	Locations []sarifLocation `json:"locations"`
}

type sarifMessageText struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           sarifRegion           `json:"region"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"`
}

// severityToLevel maps a Finding severity to a SARIF level string.
func severityToLevel(s normalizer.Severity) string {
	switch s {
	case normalizer.SeverityCritical, normalizer.SeverityHigh:
		return "error"
	case normalizer.SeverityMedium:
		return "warning"
	default: // low, info
		return "note"
	}
}

// BuildSARIF converts a slice of findings into a SARIF 2.1.0 document.
func BuildSARIF(findings []normalizer.Finding, toolVersion string) sarifRoot {
	// Collect unique rules (by RuleID).
	seen := map[string]bool{}
	rules := []sarifRule{}
	for _, f := range findings {
		ruleID := f.RuleID
		if ruleID == "" {
			ruleID = f.ID
		}
		if !seen[ruleID] {
			seen[ruleID] = true
			rules = append(rules, sarifRule{
				ID:               ruleID,
				Name:             f.Title,
				ShortDescription: sarifMessageText{Text: f.Title},
			})
		}
	}

	// Build results.
	results := make([]sarifResult, 0, len(findings))
	for _, f := range findings {
		ruleID := f.RuleID
		if ruleID == "" {
			ruleID = f.ID
		}
		line := f.LineNumber
		if line <= 0 {
			line = 1
		}
		results = append(results, sarifResult{
			RuleID: ruleID,
			Level:  severityToLevel(f.Severity),
			Message: sarifMessageText{Text: f.RawMessage},
			Locations: []sarifLocation{
				{
					PhysicalLocation: sarifPhysicalLocation{
						ArtifactLocation: sarifArtifactLocation{URI: f.FilePath},
						Region:           sarifRegion{StartLine: line},
					},
				},
			},
		})
	}

	return sarifRoot{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{
			{
				Tool: sarifTool{
					Driver: sarifDriver{
						Name:    "Trojan",
						Version: toolVersion,
						Rules:   rules,
					},
				},
				Results: results,
			},
		},
	}
}

// MarshalSARIF returns indented JSON bytes for the SARIF document.
func MarshalSARIF(findings []normalizer.Finding, toolVersion string) ([]byte, error) {
	doc := BuildSARIF(findings, toolVersion)
	return json.MarshalIndent(doc, "", "  ")
}
