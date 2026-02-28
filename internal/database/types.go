package database

import "time"

// Severity levels for findings.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
)

// ResourceType identifies the kind of cloud resource.
type ResourceType string

const (
	ResourceInstance ResourceType = "instance"
	ResourceSnapshot ResourceType = "snapshot"
	ResourceReplica  ResourceType = "replica"
)

// FindingID identifies the type of waste or security finding.
type FindingID string

const (
	FindingIdleInstance        FindingID = "IDLE_INSTANCE"
	FindingOversizedInstance   FindingID = "OVERSIZED_INSTANCE"
	FindingUnencryptedStorage  FindingID = "UNENCRYPTED_STORAGE"
	FindingPublicAccess        FindingID = "PUBLIC_ACCESS"
	FindingNoAutomatedBackups  FindingID = "NO_AUTOMATED_BACKUPS"
	FindingStaleSnapshot       FindingID = "STALE_SNAPSHOT"
	FindingUnusedReadReplica   FindingID = "UNUSED_READ_REPLICA"
	FindingNoMultiAZ           FindingID = "NO_MULTI_AZ"
	FindingOldEngineVersion    FindingID = "OLD_ENGINE_VERSION"
	FindingNoDeletionProtect   FindingID = "NO_DELETION_PROTECTION"
	FindingParameterGroupDrift FindingID = "PARAMETER_GROUP_DRIFT"
)

// Finding represents a single waste, security, or operational detection.
type Finding struct {
	ID                    FindingID      `json:"id"`
	Severity              Severity       `json:"severity"`
	ResourceType          ResourceType   `json:"resource_type"`
	ResourceID            string         `json:"resource_id"`
	ResourceName          string         `json:"resource_name,omitempty"`
	Region                string         `json:"region"`
	Message               string         `json:"message"`
	EstimatedMonthlyWaste float64        `json:"estimated_monthly_waste"`
	Metadata              map[string]any `json:"metadata,omitempty"`
}

// ScanResult holds aggregated findings from scanning a region.
type ScanResult struct {
	Findings         []Finding `json:"findings"`
	Errors           []string  `json:"errors,omitempty"`
	ResourcesScanned int       `json:"resources_scanned"`
	InstancesScanned int       `json:"instances_scanned"`
}

// ScanConfig controls scan behavior.
type ScanConfig struct {
	IdleDays       int     // days of low activity to flag as idle
	CPUThreshold   float64 // p95 CPU below this = oversized (default 20.0)
	IdleCPU        float64 // avg CPU below this = idle (default 5.0)
	MetricDays     int     // CloudWatch lookback period in days
	StaleDays      int     // snapshot age threshold
	MinMonthlyCost float64 // minimum cost to report
	Exclude        ExcludeConfig
}

// ExcludeConfig controls resource exclusion.
type ExcludeConfig struct {
	ResourceIDs map[string]bool   `json:"resource_ids,omitempty"`
	Tags        map[string]string `json:"tags,omitempty"`
}

// ScanProgress reports scanning progress.
type ScanProgress struct {
	Region    string    `json:"region"`
	Scanner   string    `json:"scanner"`
	Message   string    `json:"message"`
	Timestamp time.Time `json:"timestamp"`
}
