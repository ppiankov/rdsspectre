package rds

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/ppiankov/rdsspectre/internal/database"
	"github.com/ppiankov/rdsspectre/internal/pricing"
)

// RDSScanner audits AWS RDS instances for waste and security issues.
type RDSScanner struct {
	client RDSAPI
	cw     CloudWatchAPI
	region string
	now    time.Time
}

// NewRDSScanner creates a scanner for the given RDS and CloudWatch clients.
func NewRDSScanner(client RDSAPI, cw CloudWatchAPI, region string) *RDSScanner {
	return &RDSScanner{
		client: client,
		cw:     cw,
		region: region,
		now:    time.Now(),
	}
}

// Scan implements database.DatabaseScanner.
func (s *RDSScanner) Scan(ctx context.Context, cfg database.ScanConfig, progress func(database.ScanProgress)) *database.ScanResult {
	result := &database.ScanResult{}

	s.reportProgress(progress, "Listing RDS instances")

	// Scan instances
	instances, err := ListInstances(ctx, s.client)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("list instances: %v", err))
		return result
	}

	result.InstancesScanned = len(instances)
	s.reportProgress(progress, fmt.Sprintf("Found %d instances", len(instances)))

	for _, inst := range instances {
		if inst.Status != "available" {
			continue
		}
		// WO-9: use shared ExcludeConfig.IsExcluded helper instead of inline map lookup.
		if cfg.Exclude.IsExcluded(inst.ID) {
			continue
		}
		// WO-7: skip instances matching a configured exclude.tags rule.
		if len(cfg.Exclude.Tags) > 0 {
			tags, err := FetchTags(ctx, s.client, inst.ARN)
			if err != nil {
				slog.Warn("Failed to fetch tags for tag-based exclusion", "instance", inst.ID, "error", err)
			} else if cfg.Exclude.MatchesExcludedTags(tags) {
				continue
			}
		}
		result.ResourcesScanned++
		findings := s.analyzeInstance(ctx, cfg, inst)
		result.Findings = append(result.Findings, findings...)
	}

	// Scan snapshots
	s.reportProgress(progress, "Listing RDS snapshots")
	snapshots, err := ListSnapshots(ctx, s.client)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("list snapshots: %v", err))
	} else {
		s.reportProgress(progress, fmt.Sprintf("Found %d manual snapshots", len(snapshots)))
		for _, snap := range snapshots {
			// WO-9: use shared ExcludeConfig.IsExcluded helper instead of inline map lookup.
			if cfg.Exclude.IsExcluded(snap.ID) {
				continue
			}
			result.ResourcesScanned++
			findings := s.analyzeSnapshot(cfg, snap)
			result.Findings = append(result.Findings, findings...)
		}
	}

	s.reportProgress(progress, fmt.Sprintf("Scan complete: %d findings", len(result.Findings)))
	return result
}

func (s *RDSScanner) analyzeInstance(ctx context.Context, cfg database.ScanConfig, inst Instance) []database.Finding {
	var findings []database.Finding
	monthlyCost := pricing.MonthlyInstanceCost("rds", inst.Class) + pricing.MonthlyStorageCost("rds", int64(inst.AllocatedStorageGB))

	// Config-based checks (no CloudWatch needed)
	if !inst.StorageEncrypted {
		findings = append(findings, database.Finding{
			ID:           database.FindingUnencryptedStorage,
			Severity:     database.SeverityCritical,
			ResourceType: database.ResourceInstance,
			ResourceID:   inst.ID,
			Region:       s.region,
			Message:      fmt.Sprintf("Storage is not encrypted (%s %s)", inst.Engine, inst.Class),
			Metadata:     map[string]any{"engine": inst.Engine, "instance_class": inst.Class},
		})
	}

	if inst.PubliclyAccessible {
		findings = append(findings, database.Finding{
			ID:           database.FindingPublicAccess,
			Severity:     database.SeverityCritical,
			ResourceType: database.ResourceInstance,
			ResourceID:   inst.ID,
			Region:       s.region,
			Message:      fmt.Sprintf("Instance is publicly accessible (%s)", inst.Engine),
			Metadata:     map[string]any{"engine": inst.Engine, "instance_class": inst.Class},
		})
	}

	if inst.BackupRetentionPeriod == 0 {
		findings = append(findings, database.Finding{
			ID:           database.FindingNoAutomatedBackups,
			Severity:     database.SeverityCritical,
			ResourceType: database.ResourceInstance,
			ResourceID:   inst.ID,
			Region:       s.region,
			Message:      fmt.Sprintf("No automated backups configured (%s %s)", inst.Engine, inst.Class),
			Metadata:     map[string]any{"engine": inst.Engine, "instance_class": inst.Class},
		})
	}

	if !inst.MultiAZ {
		findings = append(findings, database.Finding{
			ID:           database.FindingNoMultiAZ,
			Severity:     database.SeverityHigh,
			ResourceType: database.ResourceInstance,
			ResourceID:   inst.ID,
			Region:       s.region,
			Message:      fmt.Sprintf("Not configured for Multi-AZ (%s %s)", inst.Engine, inst.Class),
			Metadata:     map[string]any{"engine": inst.Engine, "instance_class": inst.Class},
		})
	}

	if !inst.DeletionProtection {
		findings = append(findings, database.Finding{
			ID:           database.FindingNoDeletionProtect,
			Severity:     database.SeverityMedium,
			ResourceType: database.ResourceInstance,
			ResourceID:   inst.ID,
			Region:       s.region,
			Message:      fmt.Sprintf("Deletion protection is disabled (%s %s)", inst.Engine, inst.Class),
			Metadata:     map[string]any{"engine": inst.Engine, "instance_class": inst.Class},
		})
	}

	// Engine version check
	behind := VersionsBehind(inst.Engine, inst.EngineVersion)
	if behind >= 2 {
		findings = append(findings, database.Finding{
			ID:           database.FindingOldEngineVersion,
			Severity:     database.SeverityMedium,
			ResourceType: database.ResourceInstance,
			ResourceID:   inst.ID,
			Region:       s.region,
			Message:      fmt.Sprintf("Engine %s %s is %d major versions behind", inst.Engine, inst.EngineVersion, behind),
			Metadata: map[string]any{
				"engine":          inst.Engine,
				"current_version": inst.EngineVersion,
				"versions_behind": behind,
			},
		})
	}

	// Parameter group drift
	for _, pg := range inst.ParameterGroups {
		if !strings.HasPrefix(pg.Name, "default.") || pg.ApplyStatus != "in-sync" {
			findings = append(findings, database.Finding{
				ID:           database.FindingParameterGroupDrift,
				Severity:     database.SeverityLow,
				ResourceType: database.ResourceInstance,
				ResourceID:   inst.ID,
				Region:       s.region,
				Message:      fmt.Sprintf("Non-default or out-of-sync parameter group: %s (%s)", pg.Name, pg.ApplyStatus),
				Metadata: map[string]any{
					"parameter_group": pg.Name,
					"apply_status":    pg.ApplyStatus,
				},
			})
			break // one finding per instance
		}
	}

	// CloudWatch metric-based checks
	if s.cw != nil && cfg.MetricDays > 0 {
		metrics, err := FetchInstanceMetrics(ctx, s.cw, inst.ID, s.now, cfg.MetricDays)
		if err == nil && metrics.HasData {
			// Idle check: avg CPU < idle threshold AND zero connections
			if metrics.AvgCPU < cfg.IdleCPU && metrics.TotalConns == 0 {
				findings = append(findings, database.Finding{
					ID:                    database.FindingIdleInstance,
					Severity:              database.SeverityHigh,
					ResourceType:          database.ResourceInstance,
					ResourceID:            inst.ID,
					Region:                s.region,
					Message:               fmt.Sprintf("Instance idle for %d days (avg CPU %.1f%%, 0 connections)", cfg.MetricDays, metrics.AvgCPU),
					EstimatedMonthlyWaste: monthlyCost,
					Metadata: map[string]any{
						"avg_cpu":        metrics.AvgCPU,
						"total_conns":    metrics.TotalConns,
						"metric_days":    cfg.MetricDays,
						"instance_class": inst.Class,
						"engine":         inst.Engine,
					},
				})
			} else if metrics.MaxCPU < cfg.CPUThreshold && metrics.TotalConns > 0 && !metrics.SwapUsed {
				// WO-16: oversized check requires max CPU < threshold AND no
				// measurable swap activity — swap usage means the instance is
				// memory-bound despite low CPU, so downsizing on CPU alone
				// would be unsafe regardless of instance class.
				findings = append(findings, database.Finding{
					ID:                    database.FindingOversizedInstance,
					Severity:              database.SeverityHigh,
					ResourceType:          database.ResourceInstance,
					ResourceID:            inst.ID,
					Region:                s.region,
					Message:               fmt.Sprintf("Instance oversized (max CPU %.1f%% over %d days)", metrics.MaxCPU, cfg.MetricDays),
					EstimatedMonthlyWaste: monthlyCost * 0.5,
					Metadata: map[string]any{
						"max_cpu":        metrics.MaxCPU,
						"avg_cpu":        metrics.AvgCPU,
						"total_conns":    metrics.TotalConns,
						"metric_days":    cfg.MetricDays,
						"instance_class": inst.Class,
						"engine":         inst.Engine,
					},
				})
			}

			// Unused read replica: is replica + zero connections
			if inst.IsReplica && metrics.TotalConns == 0 {
				findings = append(findings, database.Finding{
					ID:                    database.FindingUnusedReadReplica,
					Severity:              database.SeverityHigh,
					ResourceType:          database.ResourceReplica,
					ResourceID:            inst.ID,
					Region:                s.region,
					Message:               fmt.Sprintf("Read replica with 0 connections over %d days", cfg.MetricDays),
					EstimatedMonthlyWaste: monthlyCost,
					Metadata: map[string]any{
						"source_instance": inst.ReplicaSourceID,
						"instance_class":  inst.Class,
						"engine":          inst.Engine,
					},
				})
			}
		}
	}

	return findings
}

func (s *RDSScanner) analyzeSnapshot(cfg database.ScanConfig, snap Snapshot) []database.Finding {
	if cfg.StaleDays <= 0 || snap.CreateTime.IsZero() {
		return nil
	}

	threshold := s.now.AddDate(0, 0, -cfg.StaleDays)
	if snap.CreateTime.Before(threshold) {
		daysSince := int(s.now.Sub(snap.CreateTime).Hours() / 24)
		cost := pricing.MonthlyStorageCost("rds", int64(snap.AllocatedStorageGB))
		return []database.Finding{{
			ID:                    database.FindingStaleSnapshot,
			Severity:              database.SeverityMedium,
			ResourceType:          database.ResourceSnapshot,
			ResourceID:            snap.ID,
			ResourceName:          snap.InstanceID,
			Region:                s.region,
			Message:               fmt.Sprintf("Manual snapshot is %d days old (%d GB)", daysSince, snap.AllocatedStorageGB),
			EstimatedMonthlyWaste: cost,
			Metadata: map[string]any{
				"snapshot_id":          snap.ID,
				"instance_id":          snap.InstanceID,
				"days_old":             daysSince,
				"allocated_storage_gb": snap.AllocatedStorageGB,
				"engine":               snap.Engine,
			},
		}}
	}

	return nil
}

func (s *RDSScanner) reportProgress(progress func(database.ScanProgress), msg string) {
	// WO-9: delegate to the shared database.ReportProgress helper.
	database.ReportProgress(progress, "rds", s.region, msg)
}
