package report

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/ppiankov/rdsspectre/internal/database"
)

// SARIFReporter outputs SARIF v2.1.0.
type SARIFReporter struct {
	Writer io.Writer
}

type sarifReport struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
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
	ID               string      `json:"id"`
	ShortDescription sarifText   `json:"shortDescription"`
	DefaultConfig    sarifConfig `json:"defaultConfiguration"`
}

type sarifConfig struct {
	Level string `json:"level"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID  string     `json:"ruleId"`
	Level   string     `json:"level"`
	Message sarifText  `json:"message"`
	Locs    []sarifLoc `json:"locations,omitempty"`
	Props   sarifProps `json:"properties,omitempty"`
}

type sarifLoc struct {
	PhysicalLocation sarifPhysLoc `json:"physicalLocation"`
}

type sarifPhysLoc struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
}

type sarifArtifact struct {
	URI string `json:"uri"`
}

type sarifProps struct {
	Region                string  `json:"region,omitempty"`
	EstimatedMonthlyWaste float64 `json:"estimatedMonthlyWaste,omitempty"`
}

// Generate writes the SARIF report.
func (r *SARIFReporter) Generate(data Data) error {
	results := make([]sarifResult, 0, len(data.Findings))
	for _, f := range data.Findings {
		results = append(results, sarifResult{
			RuleID:  string(f.ID),
			Level:   sarifLevel(f.Severity),
			Message: sarifText{Text: f.Message},
			Locs: []sarifLoc{{
				PhysicalLocation: sarifPhysLoc{
					ArtifactLocation: sarifArtifact{URI: f.ResourceID},
				},
			}},
			Props: sarifProps{
				Region:                f.Region,
				EstimatedMonthlyWaste: f.EstimatedMonthlyWaste,
			},
		})
	}

	report := sarifReport{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{
				Driver: sarifDriver{
					Name:    data.Tool,
					Version: data.Version,
					Rules:   buildSARIFRules(data.Findings),
				},
			},
			Results: results,
		}},
	}

	enc := json.NewEncoder(r.Writer)
	enc.SetIndent("", "  ")
	if err := enc.Encode(report); err != nil {
		return fmt.Errorf("encode SARIF: %w", err)
	}
	return nil
}

func sarifLevel(s database.Severity) string {
	switch s {
	case database.SeverityCritical:
		return "error"
	case database.SeverityHigh:
		return "error"
	case database.SeverityMedium:
		return "warning"
	case database.SeverityLow:
		return "note"
	default:
		return "none"
	}
}

func buildSARIFRules(findings []database.Finding) []sarifRule {
	seen := make(map[database.FindingID]bool)
	var rules []sarifRule
	for _, f := range findings {
		if seen[f.ID] {
			continue
		}
		seen[f.ID] = true
		rules = append(rules, sarifRule{
			ID:               string(f.ID),
			ShortDescription: sarifText{Text: string(f.ID)},
			DefaultConfig:    sarifConfig{Level: sarifLevel(f.Severity)},
		})
	}
	return rules
}
