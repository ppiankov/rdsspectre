package rds

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	rdstypes "github.com/aws/aws-sdk-go-v2/service/rds/types"

	"github.com/ppiankov/rdsspectre/internal/database"
)

var (
	now      = time.Date(2026, 2, 28, 12, 0, 0, 0, time.UTC)
	stale120 = now.AddDate(0, 0, -120)
)

func newTestScanner(rdsClient RDSAPI, cwClient CloudWatchAPI) *RDSScanner {
	s := NewRDSScanner(rdsClient, cwClient, "us-east-1")
	s.now = now
	return s
}

func defaultCfg() database.ScanConfig {
	return database.ScanConfig{
		IdleDays:     14,
		CPUThreshold: 20.0,
		IdleCPU:      5.0,
		MetricDays:   14,
		StaleDays:    90,
	}
}

func findByID(findings []database.Finding, id database.FindingID) []database.Finding {
	var out []database.Finding
	for _, f := range findings {
		if f.ID == id {
			out = append(out, f)
		}
	}
	return out
}

// --- Config-based finding tests ---

func TestScanUnencryptedStorage(t *testing.T) {
	mock := newMockRDSClient()
	mock.instances = []rdstypes.DBInstance{
		makeInstance("mydb", "db.t3.small", "postgres", "17.2", func(i *rdstypes.DBInstance) {
			i.StorageEncrypted = aws.Bool(false)
		}),
	}
	cw := newMockCWClient()
	cw.metrics["CPUUtilization"] = makeCPUDatapoints(50, 80, 14)
	cw.metrics["DatabaseConnections"] = makeConnDatapoints(100)

	s := newTestScanner(mock, cw)
	result := s.Scan(context.Background(), defaultCfg(), nil)

	findings := findByID(result.Findings, database.FindingUnencryptedStorage)
	if len(findings) != 1 {
		t.Fatalf("expected 1 UNENCRYPTED_STORAGE, got %d", len(findings))
	}
	if findings[0].Severity != database.SeverityCritical {
		t.Errorf("severity = %q, want critical", findings[0].Severity)
	}
}

func TestScanEncryptedNotFlagged(t *testing.T) {
	mock := newMockRDSClient()
	mock.instances = []rdstypes.DBInstance{
		makeInstance("mydb", "db.t3.small", "postgres", "17.2"),
	}
	cw := newMockCWClient()
	cw.metrics["CPUUtilization"] = makeCPUDatapoints(50, 80, 14)
	cw.metrics["DatabaseConnections"] = makeConnDatapoints(100)

	s := newTestScanner(mock, cw)
	result := s.Scan(context.Background(), defaultCfg(), nil)

	if len(findByID(result.Findings, database.FindingUnencryptedStorage)) != 0 {
		t.Error("encrypted instance should not be flagged")
	}
}

func TestScanPublicAccess(t *testing.T) {
	mock := newMockRDSClient()
	mock.instances = []rdstypes.DBInstance{
		makeInstance("mydb", "db.t3.small", "mysql", "8.0.35", func(i *rdstypes.DBInstance) {
			i.PubliclyAccessible = aws.Bool(true)
		}),
	}
	cw := newMockCWClient()
	cw.metrics["CPUUtilization"] = makeCPUDatapoints(50, 80, 14)
	cw.metrics["DatabaseConnections"] = makeConnDatapoints(100)

	s := newTestScanner(mock, cw)
	result := s.Scan(context.Background(), defaultCfg(), nil)

	findings := findByID(result.Findings, database.FindingPublicAccess)
	if len(findings) != 1 {
		t.Fatalf("expected 1 PUBLIC_ACCESS, got %d", len(findings))
	}
}

func TestScanNoAutomatedBackups(t *testing.T) {
	mock := newMockRDSClient()
	mock.instances = []rdstypes.DBInstance{
		makeInstance("mydb", "db.t3.small", "postgres", "17.2", func(i *rdstypes.DBInstance) {
			i.BackupRetentionPeriod = aws.Int32(0)
		}),
	}
	cw := newMockCWClient()
	cw.metrics["CPUUtilization"] = makeCPUDatapoints(50, 80, 14)
	cw.metrics["DatabaseConnections"] = makeConnDatapoints(100)

	s := newTestScanner(mock, cw)
	result := s.Scan(context.Background(), defaultCfg(), nil)

	findings := findByID(result.Findings, database.FindingNoAutomatedBackups)
	if len(findings) != 1 {
		t.Fatalf("expected 1 NO_AUTOMATED_BACKUPS, got %d", len(findings))
	}
}

func TestScanNoMultiAZ(t *testing.T) {
	mock := newMockRDSClient()
	mock.instances = []rdstypes.DBInstance{
		makeInstance("mydb", "db.t3.small", "postgres", "17.2", func(i *rdstypes.DBInstance) {
			i.MultiAZ = aws.Bool(false)
		}),
	}
	cw := newMockCWClient()
	cw.metrics["CPUUtilization"] = makeCPUDatapoints(50, 80, 14)
	cw.metrics["DatabaseConnections"] = makeConnDatapoints(100)

	s := newTestScanner(mock, cw)
	result := s.Scan(context.Background(), defaultCfg(), nil)

	findings := findByID(result.Findings, database.FindingNoMultiAZ)
	if len(findings) != 1 {
		t.Fatalf("expected 1 NO_MULTI_AZ, got %d", len(findings))
	}
}

func TestScanNoDeletionProtection(t *testing.T) {
	mock := newMockRDSClient()
	mock.instances = []rdstypes.DBInstance{
		makeInstance("mydb", "db.t3.small", "postgres", "17.2", func(i *rdstypes.DBInstance) {
			i.DeletionProtection = aws.Bool(false)
		}),
	}
	cw := newMockCWClient()
	cw.metrics["CPUUtilization"] = makeCPUDatapoints(50, 80, 14)
	cw.metrics["DatabaseConnections"] = makeConnDatapoints(100)

	s := newTestScanner(mock, cw)
	result := s.Scan(context.Background(), defaultCfg(), nil)

	findings := findByID(result.Findings, database.FindingNoDeletionProtect)
	if len(findings) != 1 {
		t.Fatalf("expected 1 NO_DELETION_PROTECTION, got %d", len(findings))
	}
}

func TestScanOldEngineVersion(t *testing.T) {
	mock := newMockRDSClient()
	mock.instances = []rdstypes.DBInstance{
		makeInstance("mydb", "db.t3.small", "postgres", "13.4"),
	}
	cw := newMockCWClient()
	cw.metrics["CPUUtilization"] = makeCPUDatapoints(50, 80, 14)
	cw.metrics["DatabaseConnections"] = makeConnDatapoints(100)

	s := newTestScanner(mock, cw)
	result := s.Scan(context.Background(), defaultCfg(), nil)

	findings := findByID(result.Findings, database.FindingOldEngineVersion)
	if len(findings) != 1 {
		t.Fatalf("expected 1 OLD_ENGINE_VERSION, got %d", len(findings))
	}
	if findings[0].Metadata["versions_behind"].(int) < 2 {
		t.Errorf("versions_behind = %v, want >= 2", findings[0].Metadata["versions_behind"])
	}
}

func TestScanCurrentVersionNotFlagged(t *testing.T) {
	mock := newMockRDSClient()
	mock.instances = []rdstypes.DBInstance{
		makeInstance("mydb", "db.t3.small", "postgres", "17.2"),
	}
	cw := newMockCWClient()
	cw.metrics["CPUUtilization"] = makeCPUDatapoints(50, 80, 14)
	cw.metrics["DatabaseConnections"] = makeConnDatapoints(100)

	s := newTestScanner(mock, cw)
	result := s.Scan(context.Background(), defaultCfg(), nil)

	if len(findByID(result.Findings, database.FindingOldEngineVersion)) != 0 {
		t.Error("current version should not be flagged")
	}
}

func TestScanParameterGroupDrift(t *testing.T) {
	mock := newMockRDSClient()
	mock.instances = []rdstypes.DBInstance{
		makeInstance("mydb", "db.t3.small", "postgres", "17.2", func(i *rdstypes.DBInstance) {
			i.DBParameterGroups = []rdstypes.DBParameterGroupStatus{
				{DBParameterGroupName: aws.String("custom-pg"), ParameterApplyStatus: aws.String("pending-reboot")},
			}
		}),
	}
	cw := newMockCWClient()
	cw.metrics["CPUUtilization"] = makeCPUDatapoints(50, 80, 14)
	cw.metrics["DatabaseConnections"] = makeConnDatapoints(100)

	s := newTestScanner(mock, cw)
	result := s.Scan(context.Background(), defaultCfg(), nil)

	findings := findByID(result.Findings, database.FindingParameterGroupDrift)
	if len(findings) != 1 {
		t.Fatalf("expected 1 PARAMETER_GROUP_DRIFT, got %d", len(findings))
	}
}

// --- Metric-based finding tests ---

func TestScanIdleInstance(t *testing.T) {
	mock := newMockRDSClient()
	mock.instances = []rdstypes.DBInstance{
		makeInstance("idle-db", "db.t3.small", "postgres", "17.2"),
	}
	cw := newMockCWClient()
	cw.metrics["CPUUtilization"] = makeCPUDatapoints(2.0, 4.0, 14)
	cw.metrics["DatabaseConnections"] = makeConnDatapoints(0)

	s := newTestScanner(mock, cw)
	result := s.Scan(context.Background(), defaultCfg(), nil)

	findings := findByID(result.Findings, database.FindingIdleInstance)
	if len(findings) != 1 {
		t.Fatalf("expected 1 IDLE_INSTANCE, got %d", len(findings))
	}
	if findings[0].EstimatedMonthlyWaste <= 0 {
		t.Error("idle instance should have non-zero waste")
	}
}

func TestScanOversizedInstance(t *testing.T) {
	mock := newMockRDSClient()
	mock.instances = []rdstypes.DBInstance{
		makeInstance("big-db", "db.r5.xlarge", "postgres", "17.2"),
	}
	cw := newMockCWClient()
	cw.metrics["CPUUtilization"] = makeCPUDatapoints(8.0, 15.0, 14)
	cw.metrics["DatabaseConnections"] = makeConnDatapoints(50)

	s := newTestScanner(mock, cw)
	result := s.Scan(context.Background(), defaultCfg(), nil)

	findings := findByID(result.Findings, database.FindingOversizedInstance)
	if len(findings) != 1 {
		t.Fatalf("expected 1 OVERSIZED_INSTANCE, got %d", len(findings))
	}
}

func TestScanActiveInstanceNotFlagged(t *testing.T) {
	mock := newMockRDSClient()
	mock.instances = []rdstypes.DBInstance{
		makeInstance("active-db", "db.t3.small", "postgres", "17.2"),
	}
	cw := newMockCWClient()
	cw.metrics["CPUUtilization"] = makeCPUDatapoints(50.0, 80.0, 14)
	cw.metrics["DatabaseConnections"] = makeConnDatapoints(200)

	s := newTestScanner(mock, cw)
	result := s.Scan(context.Background(), defaultCfg(), nil)

	if len(findByID(result.Findings, database.FindingIdleInstance)) != 0 {
		t.Error("active instance should not be flagged as idle")
	}
	if len(findByID(result.Findings, database.FindingOversizedInstance)) != 0 {
		t.Error("active instance should not be flagged as oversized")
	}
}

func TestScanUnusedReadReplica(t *testing.T) {
	mock := newMockRDSClient()
	mock.instances = []rdstypes.DBInstance{
		makeInstance("replica-db", "db.t3.small", "postgres", "17.2", func(i *rdstypes.DBInstance) {
			i.ReadReplicaSourceDBInstanceIdentifier = aws.String("primary-db")
		}),
	}
	cw := newMockCWClient()
	cw.metrics["CPUUtilization"] = makeCPUDatapoints(2.0, 4.0, 14)
	cw.metrics["DatabaseConnections"] = makeConnDatapoints(0)

	s := newTestScanner(mock, cw)
	result := s.Scan(context.Background(), defaultCfg(), nil)

	findings := findByID(result.Findings, database.FindingUnusedReadReplica)
	if len(findings) != 1 {
		t.Fatalf("expected 1 UNUSED_READ_REPLICA, got %d", len(findings))
	}
	if findings[0].Metadata["source_instance"] != "primary-db" {
		t.Errorf("source_instance = %v, want primary-db", findings[0].Metadata["source_instance"])
	}
}

// --- Snapshot tests ---

func TestScanStaleSnapshot(t *testing.T) {
	mock := newMockRDSClient()
	mock.snapshots = []rdstypes.DBSnapshot{
		makeSnapshot("snap-old", "mydb", "postgres", stale120, 50),
	}
	cw := newMockCWClient()

	s := newTestScanner(mock, cw)
	result := s.Scan(context.Background(), defaultCfg(), nil)

	findings := findByID(result.Findings, database.FindingStaleSnapshot)
	if len(findings) != 1 {
		t.Fatalf("expected 1 STALE_SNAPSHOT, got %d", len(findings))
	}
	if findings[0].EstimatedMonthlyWaste <= 0 {
		t.Error("stale snapshot should have non-zero waste")
	}
}

func TestScanRecentSnapshotNotFlagged(t *testing.T) {
	mock := newMockRDSClient()
	recent := now.AddDate(0, 0, -10)
	mock.snapshots = []rdstypes.DBSnapshot{
		makeSnapshot("snap-new", "mydb", "postgres", recent, 50),
	}
	cw := newMockCWClient()

	s := newTestScanner(mock, cw)
	result := s.Scan(context.Background(), defaultCfg(), nil)

	if len(findByID(result.Findings, database.FindingStaleSnapshot)) != 0 {
		t.Error("recent snapshot should not be flagged")
	}
}

// --- Error handling tests ---

func TestScanDescribeInstancesError(t *testing.T) {
	mock := newMockRDSClient()
	mock.descInstErr = errors.New("access denied")
	cw := newMockCWClient()

	s := newTestScanner(mock, cw)
	result := s.Scan(context.Background(), defaultCfg(), nil)

	if len(result.Errors) == 0 {
		t.Error("expected error in result.Errors")
	}
}

func TestScanDescribeSnapshotsError(t *testing.T) {
	mock := newMockRDSClient()
	mock.descSnapErr = errors.New("throttled")
	cw := newMockCWClient()

	s := newTestScanner(mock, cw)
	result := s.Scan(context.Background(), defaultCfg(), nil)

	if len(result.Errors) == 0 {
		t.Error("expected error in result.Errors for snapshot listing")
	}
}

func TestScanExcludeInstance(t *testing.T) {
	mock := newMockRDSClient()
	mock.instances = []rdstypes.DBInstance{
		makeInstance("excluded-db", "db.t3.small", "postgres", "17.2", func(i *rdstypes.DBInstance) {
			i.StorageEncrypted = aws.Bool(false) // would normally be flagged
		}),
	}
	cw := newMockCWClient()

	cfg := defaultCfg()
	cfg.Exclude.ResourceIDs = map[string]bool{"excluded-db": true}

	s := newTestScanner(mock, cw)
	result := s.Scan(context.Background(), cfg, nil)

	if len(result.Findings) != 0 {
		t.Error("excluded instance should have no findings")
	}
}

func TestScanSkipsNonAvailableInstances(t *testing.T) {
	mock := newMockRDSClient()
	mock.instances = []rdstypes.DBInstance{
		makeInstance("creating-db", "db.t3.small", "postgres", "17.2", func(i *rdstypes.DBInstance) {
			i.DBInstanceStatus = aws.String("creating")
			i.StorageEncrypted = aws.Bool(false)
		}),
	}
	cw := newMockCWClient()

	s := newTestScanner(mock, cw)
	result := s.Scan(context.Background(), defaultCfg(), nil)

	if result.ResourcesScanned != 0 {
		t.Errorf("ResourcesScanned = %d, want 0 (creating instance skipped)", result.ResourcesScanned)
	}
}

func TestScanProgress(t *testing.T) {
	mock := newMockRDSClient()
	mock.instances = []rdstypes.DBInstance{
		makeInstance("mydb", "db.t3.small", "postgres", "17.2"),
	}
	cw := newMockCWClient()
	cw.metrics["CPUUtilization"] = makeCPUDatapoints(50, 80, 14)
	cw.metrics["DatabaseConnections"] = makeConnDatapoints(100)

	var messages []string
	progress := func(p database.ScanProgress) {
		messages = append(messages, p.Message)
	}

	s := newTestScanner(mock, cw)
	s.Scan(context.Background(), defaultCfg(), progress)

	if len(messages) < 3 {
		t.Errorf("expected at least 3 progress messages, got %d", len(messages))
	}
}

func TestScanResourcesCount(t *testing.T) {
	mock := newMockRDSClient()
	mock.instances = []rdstypes.DBInstance{
		makeInstance("db1", "db.t3.small", "postgres", "17.2"),
		makeInstance("db2", "db.t3.small", "mysql", "8.0.35"),
	}
	mock.snapshots = []rdstypes.DBSnapshot{
		makeSnapshot("snap1", "db1", "postgres", stale120, 50),
	}
	cw := newMockCWClient()
	cw.metrics["CPUUtilization"] = makeCPUDatapoints(50, 80, 14)
	cw.metrics["DatabaseConnections"] = makeConnDatapoints(100)

	s := newTestScanner(mock, cw)
	result := s.Scan(context.Background(), defaultCfg(), nil)

	if result.InstancesScanned != 2 {
		t.Errorf("InstancesScanned = %d, want 2", result.InstancesScanned)
	}
	if result.ResourcesScanned != 3 {
		t.Errorf("ResourcesScanned = %d, want 3 (2 instances + 1 snapshot)", result.ResourcesScanned)
	}
}

func TestScanNoCWClient(t *testing.T) {
	mock := newMockRDSClient()
	mock.instances = []rdstypes.DBInstance{
		makeInstance("mydb", "db.t3.small", "postgres", "17.2", func(i *rdstypes.DBInstance) {
			i.StorageEncrypted = aws.Bool(false)
		}),
	}

	s := newTestScanner(mock, nil) // no CloudWatch client
	result := s.Scan(context.Background(), defaultCfg(), nil)

	// Should still produce config-based findings
	if len(findByID(result.Findings, database.FindingUnencryptedStorage)) != 1 {
		t.Error("should still find UNENCRYPTED_STORAGE without CloudWatch")
	}
	// Should NOT produce metric-based findings
	if len(findByID(result.Findings, database.FindingIdleInstance)) != 0 {
		t.Error("should not produce IDLE_INSTANCE without CloudWatch")
	}
}

func TestDerefBoolNil(t *testing.T) {
	if derefBool(nil) != false {
		t.Error("derefBool(nil) should return false")
	}
	v := true
	if derefBool(&v) != true {
		t.Error("derefBool(&true) should return true")
	}
}

func TestDerefInt32Nil(t *testing.T) {
	if derefInt32(nil) != 0 {
		t.Error("derefInt32(nil) should return 0")
	}
	v := int32(42)
	if derefInt32(&v) != 42 {
		t.Error("derefInt32(&42) should return 42")
	}
}

func TestConvertInstanceWithReplicas(t *testing.T) {
	inst := makeInstance("primary-db", "db.r5.large", "postgres", "17.2", func(i *rdstypes.DBInstance) {
		i.ReadReplicaDBInstanceIdentifiers = []string{"replica-1", "replica-2"}
		i.DBParameterGroups = []rdstypes.DBParameterGroupStatus{
			{
				DBParameterGroupName: aws.String("custom-pg"),
				ParameterApplyStatus: aws.String("in-sync"),
			},
		}
	})
	converted := convertInstance(inst)
	if len(converted.ReplicaIDs) != 2 {
		t.Errorf("ReplicaIDs = %d, want 2", len(converted.ReplicaIDs))
	}
	if len(converted.ParameterGroups) != 1 {
		t.Errorf("ParameterGroups = %d, want 1", len(converted.ParameterGroups))
	}
}

func TestConvertInstanceNilCreateTime(t *testing.T) {
	inst := makeInstance("no-time-db", "db.t3.small", "postgres", "17.2", func(i *rdstypes.DBInstance) {
		i.InstanceCreateTime = nil
	})
	converted := convertInstance(inst)
	if !converted.CreateTime.IsZero() {
		t.Error("CreateTime should be zero for nil InstanceCreateTime")
	}
}

func TestConvertInstanceIsReplicaEmptyString(t *testing.T) {
	empty := ""
	inst := makeInstance("not-replica", "db.t3.small", "postgres", "17.2", func(i *rdstypes.DBInstance) {
		i.ReadReplicaSourceDBInstanceIdentifier = &empty
	})
	converted := convertInstance(inst)
	if converted.IsReplica {
		t.Error("empty string ReplicaSourceID should not be treated as replica")
	}
}

func TestConvertSnapshot(t *testing.T) {
	snap := makeSnapshot("snap-1", "mydb", "postgres", now, 100)
	converted := convertSnapshot(snap)
	if converted.ID != "snap-1" {
		t.Errorf("ID = %q, want snap-1", converted.ID)
	}
	if converted.InstanceID != "mydb" {
		t.Errorf("InstanceID = %q, want mydb", converted.InstanceID)
	}
	if converted.AllocatedStorageGB != 100 {
		t.Errorf("AllocatedStorageGB = %d, want 100", converted.AllocatedStorageGB)
	}
	if converted.CreateTime.IsZero() {
		t.Error("CreateTime should be set")
	}
}

func TestConvertSnapshotNilTime(t *testing.T) {
	snap := makeSnapshot("snap-2", "mydb", "postgres", now, 50)
	snap.SnapshotCreateTime = nil
	converted := convertSnapshot(snap)
	if !converted.CreateTime.IsZero() {
		t.Error("CreateTime should be zero for nil SnapshotCreateTime")
	}
}

func TestScanAnalyzeSnapshotZeroCreateTime(t *testing.T) {
	mock := newMockRDSClient()
	mock.instances = []rdstypes.DBInstance{
		makeInstance("mydb", "db.t3.small", "postgres", "17.2"),
	}
	snap := makeSnapshot("no-time-snap", "mydb", "postgres", now, 50)
	snap.SnapshotCreateTime = nil
	mock.snapshots = []rdstypes.DBSnapshot{snap}
	cw := newMockCWClient()
	cw.metrics["CPUUtilization"] = makeCPUDatapoints(50, 80, 14)
	cw.metrics["DatabaseConnections"] = makeConnDatapoints(100)

	s := newTestScanner(mock, cw)
	result := s.Scan(context.Background(), defaultCfg(), nil)

	if len(findByID(result.Findings, database.FindingStaleSnapshot)) != 0 {
		t.Error("snapshot with zero time should not be flagged as stale")
	}
}

func TestListInstancesPagination(t *testing.T) {
	mock := newMockRDSClient()
	mock.instances = []rdstypes.DBInstance{
		makeInstance("db1", "db.t3.small", "postgres", "17.2"),
		makeInstance("db2", "db.t3.small", "mysql", "8.0.35"),
	}
	mock.instPages = 2 // 2 pages

	instances, err := ListInstances(context.Background(), mock)
	if err != nil {
		t.Fatalf("ListInstances() error: %v", err)
	}
	if len(instances) != 2 {
		t.Errorf("got %d instances, want 2", len(instances))
	}
}

func TestListSnapshotsPagination(t *testing.T) {
	mock := newMockRDSClient()
	mock.snapshots = []rdstypes.DBSnapshot{
		makeSnapshot("snap1", "db1", "postgres", stale120, 50),
		makeSnapshot("snap2", "db2", "mysql", stale120, 100),
	}
	mock.snapPages = 2

	snapshots, err := ListSnapshots(context.Background(), mock)
	if err != nil {
		t.Fatalf("ListSnapshots() error: %v", err)
	}
	if len(snapshots) != 2 {
		t.Errorf("got %d snapshots, want 2", len(snapshots))
	}
}

func TestListInstancesError(t *testing.T) {
	mock := newMockRDSClient()
	mock.descInstErr = errors.New("describe error")

	_, err := ListInstances(context.Background(), mock)
	if err == nil {
		t.Error("expected error")
	}
}

func TestListSnapshotsError(t *testing.T) {
	mock := newMockRDSClient()
	mock.descSnapErr = errors.New("describe error")

	_, err := ListSnapshots(context.Background(), mock)
	if err == nil {
		t.Error("expected error")
	}
}

func TestScanAnalyzeSnapshotZeroStaleDays(t *testing.T) {
	mock := newMockRDSClient()
	mock.instances = []rdstypes.DBInstance{
		makeInstance("mydb", "db.t3.small", "postgres", "17.2"),
	}
	mock.snapshots = []rdstypes.DBSnapshot{
		makeSnapshot("old-snap", "mydb", "postgres", stale120, 50),
	}
	cw := newMockCWClient()
	cw.metrics["CPUUtilization"] = makeCPUDatapoints(50, 80, 14)
	cw.metrics["DatabaseConnections"] = makeConnDatapoints(100)

	cfg := defaultCfg()
	cfg.StaleDays = 0 // disabled

	s := newTestScanner(mock, cw)
	result := s.Scan(context.Background(), cfg, nil)

	if len(findByID(result.Findings, database.FindingStaleSnapshot)) != 0 {
		t.Error("stale snapshot check should be disabled when StaleDays=0")
	}
}

func TestScanStaleSnapshotNotStale(t *testing.T) {
	mock := newMockRDSClient()
	mock.instances = []rdstypes.DBInstance{
		makeInstance("mydb", "db.t3.small", "postgres", "17.2"),
	}
	recentTime := now.AddDate(0, 0, -30) // only 30 days old
	mock.snapshots = []rdstypes.DBSnapshot{
		makeSnapshot("recent-snap", "mydb", "postgres", recentTime, 50),
	}
	cw := newMockCWClient()
	cw.metrics["CPUUtilization"] = makeCPUDatapoints(50, 80, 14)
	cw.metrics["DatabaseConnections"] = makeConnDatapoints(100)

	s := newTestScanner(mock, cw)
	result := s.Scan(context.Background(), defaultCfg(), nil)

	if len(findByID(result.Findings, database.FindingStaleSnapshot)) != 0 {
		t.Error("30-day old snapshot should not be stale")
	}
}
