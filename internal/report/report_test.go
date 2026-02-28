package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/ppiankov/rdsspectre/internal/analyzer"
	"github.com/ppiankov/rdsspectre/internal/database"
)

func sampleData() Data {
	return Data{
		Tool:      "rdsspectre",
		Version:   "0.1.0",
		Timestamp: time.Date(2026, 2, 28, 12, 0, 0, 0, time.UTC),
		Target:    Target{Type: "rds", URIHash: "sha256:abc"},
		Config: ReportConfig{
			Provider:       "aws",
			Regions:        []string{"us-east-1"},
			IdleDays:       14,
			StaleDays:      90,
			CPUThreshold:   20.0,
			MinMonthlyCost: 0.10,
		},
		Findings: []database.Finding{
			{
				ID:                    database.FindingIdleInstance,
				Severity:              database.SeverityHigh,
				ResourceType:          database.ResourceInstance,
				ResourceID:            "mydb-prod",
				Region:                "us-east-1",
				Message:               "Instance idle for 14 days (avg CPU 2.1%)",
				EstimatedMonthlyWaste: 124.10,
			},
			{
				ID:                    database.FindingPublicAccess,
				Severity:              database.SeverityCritical,
				ResourceType:          database.ResourceInstance,
				ResourceID:            "mydb-dev",
				Region:                "us-east-1",
				Message:               "Instance is publicly accessible",
				EstimatedMonthlyWaste: 0,
			},
		},
		Summary: analyzer.Summary{
			TotalFindings:     2,
			InstancesScanned:  5,
			ResourcesScanned:  5,
			TotalMonthlyWaste: 124.10,
			BySeverity:        map[string]int{"high": 1, "critical": 1},
			ByFindingType:     map[string]int{"IDLE_INSTANCE": 1, "PUBLIC_ACCESS": 1},
			ByRegion:          map[string]int{"us-east-1": 2},
			ByResourceType:    map[string]int{"instance": 2},
		},
	}
}

func TestJSONReporter(t *testing.T) {
	var buf bytes.Buffer
	r := &JSONReporter{Writer: &buf}
	if err := r.Generate(sampleData()); err != nil {
		t.Fatalf("Generate() error: %v", err)
	}
	var parsed map[string]any
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if parsed["schema"] != "spectre/v1" {
		t.Errorf("schema = %v, want spectre/v1", parsed["schema"])
	}
}

func TestTextReporter(t *testing.T) {
	var buf bytes.Buffer
	r := &TextReporter{Writer: &buf}
	if err := r.Generate(sampleData()); err != nil {
		t.Fatalf("Generate() error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "rdsspectre scan results") {
		t.Error("missing header")
	}
	if !strings.Contains(out, "mydb-prod") {
		t.Error("missing finding")
	}
	if !strings.Contains(out, "Summary:") {
		t.Error("missing summary")
	}
}

func TestTextReporterNoFindings(t *testing.T) {
	data := sampleData()
	data.Findings = nil
	var buf bytes.Buffer
	r := &TextReporter{Writer: &buf}
	if err := r.Generate(data); err != nil {
		t.Fatalf("Generate() error: %v", err)
	}
	if !strings.Contains(buf.String(), "No findings") {
		t.Error("should show 'No findings'")
	}
}

func TestSARIFReporter(t *testing.T) {
	var buf bytes.Buffer
	r := &SARIFReporter{Writer: &buf}
	if err := r.Generate(sampleData()); err != nil {
		t.Fatalf("Generate() error: %v", err)
	}
	var parsed map[string]any
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if parsed["version"] != "2.1.0" {
		t.Errorf("version = %v, want 2.1.0", parsed["version"])
	}
}

func TestSARIFLevel(t *testing.T) {
	tests := []struct {
		severity database.Severity
		want     string
	}{
		{database.SeverityCritical, "error"},
		{database.SeverityHigh, "error"},
		{database.SeverityMedium, "warning"},
		{database.SeverityLow, "note"},
		{"unknown", "none"},
	}
	for _, tt := range tests {
		got := sarifLevel(tt.severity)
		if got != tt.want {
			t.Errorf("sarifLevel(%q) = %q, want %q", tt.severity, got, tt.want)
		}
	}
}

func TestSARIFRulesCount(t *testing.T) {
	data := sampleData()
	rules := buildSARIFRules(data.Findings)
	if len(rules) != 2 {
		t.Errorf("rules count = %d, want 2", len(rules))
	}
}

func TestTextReporterWithErrors(t *testing.T) {
	data := sampleData()
	data.Errors = []string{"region us-west-2 failed: timeout"}
	var buf bytes.Buffer
	r := &TextReporter{Writer: &buf}
	if err := r.Generate(data); err != nil {
		t.Fatalf("Generate() error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "Errors:") {
		t.Error("missing errors section")
	}
	if !strings.Contains(out, "timeout") {
		t.Error("missing error message")
	}
}

func TestSARIFNoFindings(t *testing.T) {
	data := sampleData()
	data.Findings = nil
	var buf bytes.Buffer
	r := &SARIFReporter{Writer: &buf}
	if err := r.Generate(data); err != nil {
		t.Fatalf("Generate() error: %v", err)
	}
	if !strings.Contains(buf.String(), "2.1.0") {
		t.Error("missing SARIF version")
	}
}

func TestSARIFRulesDeduplicate(t *testing.T) {
	// Two findings with same ID should produce one rule
	findings := []database.Finding{
		{ID: database.FindingPublicAccess, Severity: database.SeverityCritical, ResourceID: "db1", Message: "test1"},
		{ID: database.FindingPublicAccess, Severity: database.SeverityCritical, ResourceID: "db2", Message: "test2"},
	}
	rules := buildSARIFRules(findings)
	if len(rules) != 1 {
		t.Errorf("rules count = %d, want 1 (deduplicated)", len(rules))
	}
}

func TestJSONReporterNoFindings(t *testing.T) {
	data := sampleData()
	data.Findings = nil
	var buf bytes.Buffer
	r := &JSONReporter{Writer: &buf}
	if err := r.Generate(data); err != nil {
		t.Fatalf("Generate() error: %v", err)
	}
	if !strings.Contains(buf.String(), "spectre/v1") {
		t.Error("missing schema")
	}
}

func TestSpectreHubNoFindings(t *testing.T) {
	data := sampleData()
	data.Findings = nil
	var buf bytes.Buffer
	r := &SpectreHubReporter{Writer: &buf}
	if err := r.Generate(data); err != nil {
		t.Fatalf("Generate() error: %v", err)
	}
	if !strings.Contains(buf.String(), "spectrehub/v1") {
		t.Error("missing schema")
	}
}

func TestSpectreHubReporter(t *testing.T) {
	var buf bytes.Buffer
	r := &SpectreHubReporter{Writer: &buf}
	if err := r.Generate(sampleData()); err != nil {
		t.Fatalf("Generate() error: %v", err)
	}
	var parsed map[string]any
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if parsed["schema"] != "spectrehub/v1" {
		t.Errorf("schema = %v, want spectrehub/v1", parsed["schema"])
	}
}
