package analyzer

import (
	"testing"

	"github.com/ppiankov/rdsspectre/internal/database"
)

func TestAnalyzeFiltersByMinCost(t *testing.T) {
	result := &database.ScanResult{
		Findings: []database.Finding{
			{ID: database.FindingIdleInstance, EstimatedMonthlyWaste: 100.0, Severity: database.SeverityHigh, Region: "us-east-1", ResourceType: database.ResourceInstance},
			{ID: database.FindingStaleSnapshot, EstimatedMonthlyWaste: 0.05, Severity: database.SeverityMedium, Region: "us-east-1", ResourceType: database.ResourceSnapshot},
		},
		InstancesScanned: 5,
		ResourcesScanned: 10,
	}

	analysis := Analyze(result, AnalyzerConfig{MinMonthlyCost: 1.0})
	if len(analysis.Findings) != 1 {
		t.Errorf("expected 1 finding after filter, got %d", len(analysis.Findings))
	}
	if analysis.Summary.TotalMonthlyWaste != 100.0 {
		t.Errorf("TotalMonthlyWaste = %f, want 100.0", analysis.Summary.TotalMonthlyWaste)
	}
}

func TestAnalyzeIncludesZeroCostFindings(t *testing.T) {
	result := &database.ScanResult{
		Findings: []database.Finding{
			{ID: database.FindingPublicAccess, EstimatedMonthlyWaste: 0, Severity: database.SeverityCritical, Region: "us-east-1", ResourceType: database.ResourceInstance},
		},
	}

	analysis := Analyze(result, AnalyzerConfig{MinMonthlyCost: 1.0})
	if len(analysis.Findings) != 1 {
		t.Error("zero-cost security findings should not be filtered")
	}
}

func TestAnalyzeSummaryHistograms(t *testing.T) {
	result := &database.ScanResult{
		Findings: []database.Finding{
			{ID: database.FindingIdleInstance, Severity: database.SeverityHigh, Region: "us-east-1", ResourceType: database.ResourceInstance},
			{ID: database.FindingPublicAccess, Severity: database.SeverityCritical, Region: "us-east-1", ResourceType: database.ResourceInstance},
			{ID: database.FindingIdleInstance, Severity: database.SeverityHigh, Region: "eu-west-1", ResourceType: database.ResourceInstance},
		},
		InstancesScanned: 3,
		ResourcesScanned: 3,
	}

	analysis := Analyze(result, AnalyzerConfig{})
	if analysis.Summary.BySeverity["high"] != 2 {
		t.Errorf("BySeverity[high] = %d, want 2", analysis.Summary.BySeverity["high"])
	}
	if analysis.Summary.ByFindingType["IDLE_INSTANCE"] != 2 {
		t.Errorf("ByFindingType[IDLE_INSTANCE] = %d, want 2", analysis.Summary.ByFindingType["IDLE_INSTANCE"])
	}
	if analysis.Summary.ByRegion["us-east-1"] != 2 {
		t.Errorf("ByRegion[us-east-1] = %d, want 2", analysis.Summary.ByRegion["us-east-1"])
	}
}

func TestAnalyzeNoFindings(t *testing.T) {
	result := &database.ScanResult{
		InstancesScanned: 5,
		ResourcesScanned: 5,
	}
	analysis := Analyze(result, AnalyzerConfig{})
	if analysis.Summary.TotalFindings != 0 {
		t.Errorf("TotalFindings = %d, want 0", analysis.Summary.TotalFindings)
	}
	if analysis.Summary.InstancesScanned != 5 {
		t.Errorf("InstancesScanned = %d, want 5", analysis.Summary.InstancesScanned)
	}
}

func TestAnalyzePreservesErrors(t *testing.T) {
	result := &database.ScanResult{
		Errors: []string{"access denied"},
	}
	analysis := Analyze(result, AnalyzerConfig{})
	if len(analysis.Errors) != 1 {
		t.Errorf("Errors len = %d, want 1", len(analysis.Errors))
	}
}
