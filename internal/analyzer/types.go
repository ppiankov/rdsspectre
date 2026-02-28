package analyzer

import "github.com/ppiankov/rdsspectre/internal/database"

// Summary holds aggregated scan statistics.
type Summary struct {
	TotalFindings     int                `json:"total_findings"`
	InstancesScanned  int                `json:"instances_scanned"`
	ResourcesScanned  int                `json:"resources_scanned"`
	TotalMonthlyWaste float64            `json:"total_monthly_waste"`
	BySeverity        map[string]int     `json:"by_severity"`
	ByFindingType     map[string]int     `json:"by_finding_type"`
	ByRegion          map[string]int     `json:"by_region"`
	ByResourceType    map[string]int     `json:"by_resource_type"`
	TopWasteResources []database.Finding `json:"top_waste_resources,omitempty"`
}

// AnalysisResult contains filtered findings and summary.
type AnalysisResult struct {
	Findings []database.Finding `json:"findings"`
	Summary  Summary            `json:"summary"`
	Errors   []string           `json:"errors,omitempty"`
}

// AnalyzerConfig controls analysis behavior.
type AnalyzerConfig struct {
	MinMonthlyCost float64
}
