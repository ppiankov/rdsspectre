package analyzer

import "github.com/ppiankov/rdsspectre/internal/database"

// Analyze filters findings and computes summary statistics.
func Analyze(result *database.ScanResult, cfg AnalyzerConfig) AnalysisResult {
	var filtered []database.Finding
	for _, f := range result.Findings {
		if f.EstimatedMonthlyWaste >= cfg.MinMonthlyCost || f.EstimatedMonthlyWaste == 0 {
			filtered = append(filtered, f)
		}
	}

	summary := Summary{
		TotalFindings:    len(filtered),
		InstancesScanned: result.InstancesScanned,
		ResourcesScanned: result.ResourcesScanned,
		BySeverity:       make(map[string]int),
		ByFindingType:    make(map[string]int),
		ByRegion:         make(map[string]int),
		ByResourceType:   make(map[string]int),
	}

	for _, f := range filtered {
		summary.TotalMonthlyWaste += f.EstimatedMonthlyWaste
		summary.BySeverity[string(f.Severity)]++
		summary.ByFindingType[string(f.ID)]++
		summary.ByRegion[f.Region]++
		summary.ByResourceType[string(f.ResourceType)]++
	}

	return AnalysisResult{
		Findings: filtered,
		Summary:  summary,
		Errors:   result.Errors,
	}
}
