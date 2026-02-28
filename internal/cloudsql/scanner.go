package cloudsql

import (
	"context"
	"fmt"
	"time"

	"github.com/ppiankov/rdsspectre/internal/database"
	"github.com/ppiankov/rdsspectre/internal/pricing"
	"github.com/ppiankov/rdsspectre/internal/rds"
)

// CloudSQLScanner audits GCP Cloud SQL instances for waste and security issues.
// Uses config-based checks only (Cloud Monitoring deferred).
type CloudSQLScanner struct {
	client  CloudSQLAPI
	project string
	now     time.Time
}

// NewCloudSQLScanner creates a scanner for the given Cloud SQL client.
func NewCloudSQLScanner(client CloudSQLAPI, project string) *CloudSQLScanner {
	return &CloudSQLScanner{
		client:  client,
		project: project,
		now:     time.Now(),
	}
}

// Scan implements database.DatabaseScanner.
func (s *CloudSQLScanner) Scan(ctx context.Context, cfg database.ScanConfig, progress func(database.ScanProgress)) *database.ScanResult {
	result := &database.ScanResult{}

	s.reportProgress(progress, "Listing Cloud SQL instances")

	instances, err := s.client.ListInstances(ctx, s.project)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("list instances: %v", err))
		return result
	}

	result.InstancesScanned = len(instances)
	s.reportProgress(progress, fmt.Sprintf("Found %d instances", len(instances)))

	for _, inst := range instances {
		if inst.State != "RUNNABLE" {
			continue
		}
		if cfg.Exclude.ResourceIDs[inst.Name] {
			continue
		}
		result.ResourcesScanned++
		findings := s.analyzeInstance(cfg, inst)
		result.Findings = append(result.Findings, findings...)
	}

	s.reportProgress(progress, fmt.Sprintf("Scan complete: %d findings", len(result.Findings)))
	return result
}

func (s *CloudSQLScanner) analyzeInstance(cfg database.ScanConfig, inst Instance) []database.Finding {
	var findings []database.Finding
	region := inst.Region
	monthlyCost := pricing.MonthlyInstanceCost("cloudsql", inst.Tier) + pricing.MonthlyStorageCost("cloudsql", inst.DataDiskSizeGB)

	// UNENCRYPTED_STORAGE: Cloud SQL instances without CMEK are encrypted with Google-managed keys.
	// The ipConfiguration check here flags if IPv4 is enabled without SSL requirement,
	// which is a weaker signal. For Cloud SQL, the main encryption concern is CMEK absence.
	// Since Cloud SQL doesn't expose a simple "encrypted" boolean like RDS,
	// we skip this check — all Cloud SQL storage is encrypted by default with Google-managed keys.

	// PUBLIC_ACCESS: 0.0.0.0/0 in authorized networks
	if hasPublicAccess(inst) {
		findings = append(findings, database.Finding{
			ID:           database.FindingPublicAccess,
			Severity:     database.SeverityCritical,
			ResourceType: database.ResourceInstance,
			ResourceID:   inst.Name,
			Region:       region,
			Message:      fmt.Sprintf("Instance has 0.0.0.0/0 in authorized networks (%s)", inst.DatabaseVersion),
			Metadata:     map[string]any{"database_version": inst.DatabaseVersion, "tier": inst.Tier},
		})
	}

	// NO_AUTOMATED_BACKUPS
	if !inst.BackupEnabled {
		findings = append(findings, database.Finding{
			ID:           database.FindingNoAutomatedBackups,
			Severity:     database.SeverityCritical,
			ResourceType: database.ResourceInstance,
			ResourceID:   inst.Name,
			Region:       region,
			Message:      fmt.Sprintf("Automated backups disabled (%s %s)", inst.DatabaseVersion, inst.Tier),
			Metadata:     map[string]any{"database_version": inst.DatabaseVersion, "tier": inst.Tier},
		})
	}

	// NO_MULTI_AZ: ZONAL availability
	if inst.AvailabilityType == "ZONAL" {
		findings = append(findings, database.Finding{
			ID:           database.FindingNoMultiAZ,
			Severity:     database.SeverityHigh,
			ResourceType: database.ResourceInstance,
			ResourceID:   inst.Name,
			Region:       region,
			Message:      fmt.Sprintf("Instance is ZONAL (no high availability) (%s %s)", inst.DatabaseVersion, inst.Tier),
			Metadata:     map[string]any{"database_version": inst.DatabaseVersion, "tier": inst.Tier, "availability_type": inst.AvailabilityType},
		})
	}

	// NO_DELETION_PROTECTION
	if !inst.DeletionProtection {
		findings = append(findings, database.Finding{
			ID:           database.FindingNoDeletionProtect,
			Severity:     database.SeverityMedium,
			ResourceType: database.ResourceInstance,
			ResourceID:   inst.Name,
			Region:       region,
			Message:      fmt.Sprintf("Deletion protection is disabled (%s %s)", inst.DatabaseVersion, inst.Tier),
			Metadata:     map[string]any{"database_version": inst.DatabaseVersion, "tier": inst.Tier},
		})
	}

	// OLD_ENGINE_VERSION: 2+ major versions behind
	behind := rds.VersionsBehind(inst.DatabaseVersion, "")
	if behind >= 2 {
		findings = append(findings, database.Finding{
			ID:           database.FindingOldEngineVersion,
			Severity:     database.SeverityMedium,
			ResourceType: database.ResourceInstance,
			ResourceID:   inst.Name,
			Region:       region,
			Message:      fmt.Sprintf("Database version %s is %d major versions behind", inst.DatabaseVersion, behind),
			Metadata: map[string]any{
				"database_version": inst.DatabaseVersion,
				"versions_behind":  behind,
			},
		})
	}

	// UNUSED_READ_REPLICA: config-based detection (no metrics)
	if inst.IsReplica {
		findings = append(findings, database.Finding{
			ID:                    database.FindingUnusedReadReplica,
			Severity:              database.SeverityHigh,
			ResourceType:          database.ResourceReplica,
			ResourceID:            inst.Name,
			Region:                region,
			Message:               "Read replica detected (connection metrics unavailable without Cloud Monitoring)",
			EstimatedMonthlyWaste: monthlyCost,
			Metadata: map[string]any{
				"master_instance":  inst.MasterInstanceName,
				"database_version": inst.DatabaseVersion,
				"tier":             inst.Tier,
			},
		})
	}

	return findings
}

// hasPublicAccess checks if any authorized network CIDR is 0.0.0.0/0.
func hasPublicAccess(inst Instance) bool {
	for _, cidr := range inst.AuthorizedNetworks {
		if cidr == "0.0.0.0/0" {
			return true
		}
	}
	return false
}

func (s *CloudSQLScanner) reportProgress(progress func(database.ScanProgress), msg string) {
	if progress != nil {
		progress(database.ScanProgress{
			Region:    s.project,
			Scanner:   "cloudsql",
			Message:   msg,
			Timestamp: time.Now(),
		})
	}
}
