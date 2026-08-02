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

// Confidence grades how much corroborating evidence backs a cost finding.
// WO-17: cost findings are graded, never suppressed — a countersignal that
// contradicts the primary signal is information the operator needs, so it
// downgrades confidence and is reported rather than hiding the finding.
type Confidence string

const (
	// ConfidenceConfident means no countersignal contradicted the primary signal.
	ConfidenceConfident Confidence = "confident"
	// ConfidenceNeedsReview means at least one countersignal disagreed; the
	// estimated waste may not be safely realizable without further checks.
	ConfidenceNeedsReview Confidence = "needs_review"
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
	// WO-17: grading fields. Both omitempty so existing spectre/v1 consumers
	// that predate grading keep parsing unchanged.
	Confidence Confidence `json:"confidence,omitempty"`
	// Countersignals are human-readable reasons confidence was downgraded,
	// e.g. "swap grew 5.7MB over 14d". Empty when the finding is confident.
	Countersignals []string `json:"countersignals,omitempty"`
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

// WO-9: shared by rds/scanner.go and cloudsql/scanner.go instead of an inline lookup.
// IsExcluded reports whether id is in the resource-ID exclusion list.
func (e ExcludeConfig) IsExcluded(id string) bool {
	return e.ResourceIDs[id]
}

// WO-7: tag/label-based exclusion for both AWS and GCP scanners.
// MatchesExcludedTags reports whether tags matches any configured exclusion
// rule. A configured value of "" matches any value for that key (key-only
// exclusion, mirroring commands.parseExcludeTags's key-only tag syntax).
func (e ExcludeConfig) MatchesExcludedTags(tags map[string]string) bool {
	for k, want := range e.Tags {
		if got, ok := tags[k]; ok && (want == "" || got == want) {
			return true
		}
	}
	return false
}

// ScanProgress reports scanning progress.
type ScanProgress struct {
	Region    string    `json:"region"`
	Scanner   string    `json:"scanner"`
	Message   string    `json:"message"`
	Timestamp time.Time `json:"timestamp"`
}

// WO-9: shared by rds/scanner.go and cloudsql/scanner.go instead of duplicated boilerplate.
// ReportProgress invokes progress with a ScanProgress if progress is non-nil.
// Shared by per-provider scanners to avoid re-implementing the same guard.
func ReportProgress(progress func(ScanProgress), scanner, region, msg string) {
	if progress != nil {
		progress(ScanProgress{
			Region:    region,
			Scanner:   scanner,
			Message:   msg,
			Timestamp: time.Now(),
		})
	}
}
