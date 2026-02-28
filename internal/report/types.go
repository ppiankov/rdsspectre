package report

import (
	"time"

	"github.com/ppiankov/rdsspectre/internal/analyzer"
	"github.com/ppiankov/rdsspectre/internal/database"
)

// Reporter generates output in a specific format.
type Reporter interface {
	Generate(data Data) error
}

// Data is the envelope for all report formats.
type Data struct {
	Tool      string             `json:"tool"`
	Version   string             `json:"version"`
	Timestamp time.Time          `json:"timestamp"`
	Target    Target             `json:"target"`
	Config    ReportConfig       `json:"config"`
	Findings  []database.Finding `json:"findings"`
	Summary   analyzer.Summary   `json:"summary"`
	Errors    []string           `json:"errors,omitempty"`
}

// Target identifies what was scanned.
type Target struct {
	Type    string `json:"type"`
	URIHash string `json:"uri_hash"`
}

// ReportConfig captures the scan configuration.
type ReportConfig struct {
	Provider       string   `json:"provider"`
	Regions        []string `json:"regions"`
	IdleDays       int      `json:"idle_days"`
	StaleDays      int      `json:"stale_days"`
	CPUThreshold   float64  `json:"cpu_threshold"`
	MinMonthlyCost float64  `json:"min_monthly_cost"`
}
