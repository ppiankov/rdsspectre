package cloudsql

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ppiankov/rdsspectre/internal/database"
)

var now = time.Date(2026, 2, 28, 12, 0, 0, 0, time.UTC)

func newTestScanner(client CloudSQLAPI) *CloudSQLScanner {
	s := NewCloudSQLScanner(client, "test-project")
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

func TestScanPublicAccess(t *testing.T) {
	mock := newMockClient()
	mock.instances = []Instance{
		makeInstance("public-db", "db-f1-micro", "POSTGRES_17", func(i *Instance) {
			i.AuthorizedNetworks = []string{"10.0.0.0/8", "0.0.0.0/0"}
		}),
	}

	s := newTestScanner(mock)
	result := s.Scan(context.Background(), defaultCfg(), nil)

	hits := findByID(result.Findings, database.FindingPublicAccess)
	if len(hits) != 1 {
		t.Errorf("expected 1 PUBLIC_ACCESS finding, got %d", len(hits))
	}
}

func TestScanNoPublicAccess(t *testing.T) {
	mock := newMockClient()
	mock.instances = []Instance{
		makeInstance("private-db", "db-f1-micro", "POSTGRES_17", func(i *Instance) {
			i.AuthorizedNetworks = []string{"10.0.0.0/8"}
		}),
	}

	s := newTestScanner(mock)
	result := s.Scan(context.Background(), defaultCfg(), nil)

	if len(findByID(result.Findings, database.FindingPublicAccess)) != 0 {
		t.Error("should not flag private network")
	}
}

func TestScanNoAutomatedBackups(t *testing.T) {
	mock := newMockClient()
	mock.instances = []Instance{
		makeInstance("no-backup-db", "db-f1-micro", "MYSQL_8_0", func(i *Instance) {
			i.BackupEnabled = false
		}),
	}

	s := newTestScanner(mock)
	result := s.Scan(context.Background(), defaultCfg(), nil)

	hits := findByID(result.Findings, database.FindingNoAutomatedBackups)
	if len(hits) != 1 {
		t.Errorf("expected 1 NO_AUTOMATED_BACKUPS finding, got %d", len(hits))
	}
}

func TestScanBackupsEnabled(t *testing.T) {
	mock := newMockClient()
	mock.instances = []Instance{
		makeInstance("good-db", "db-f1-micro", "MYSQL_8_0"),
	}

	s := newTestScanner(mock)
	result := s.Scan(context.Background(), defaultCfg(), nil)

	if len(findByID(result.Findings, database.FindingNoAutomatedBackups)) != 0 {
		t.Error("should not flag instance with backups enabled")
	}
}

func TestScanZonalAvailability(t *testing.T) {
	mock := newMockClient()
	mock.instances = []Instance{
		makeInstance("zonal-db", "db-f1-micro", "POSTGRES_17", func(i *Instance) {
			i.AvailabilityType = "ZONAL"
		}),
	}

	s := newTestScanner(mock)
	result := s.Scan(context.Background(), defaultCfg(), nil)

	hits := findByID(result.Findings, database.FindingNoMultiAZ)
	if len(hits) != 1 {
		t.Errorf("expected 1 NO_MULTI_AZ finding, got %d", len(hits))
	}
}

func TestScanRegionalAvailability(t *testing.T) {
	mock := newMockClient()
	mock.instances = []Instance{
		makeInstance("regional-db", "db-f1-micro", "POSTGRES_17"),
	}

	s := newTestScanner(mock)
	result := s.Scan(context.Background(), defaultCfg(), nil)

	if len(findByID(result.Findings, database.FindingNoMultiAZ)) != 0 {
		t.Error("should not flag REGIONAL instance")
	}
}

func TestScanNoDeletionProtection(t *testing.T) {
	mock := newMockClient()
	mock.instances = []Instance{
		makeInstance("unprotected-db", "db-f1-micro", "POSTGRES_17", func(i *Instance) {
			i.DeletionProtection = false
		}),
	}

	s := newTestScanner(mock)
	result := s.Scan(context.Background(), defaultCfg(), nil)

	hits := findByID(result.Findings, database.FindingNoDeletionProtect)
	if len(hits) != 1 {
		t.Errorf("expected 1 NO_DELETION_PROTECTION finding, got %d", len(hits))
	}
}

func TestScanDeletionProtectionEnabled(t *testing.T) {
	mock := newMockClient()
	mock.instances = []Instance{
		makeInstance("protected-db", "db-f1-micro", "POSTGRES_17"),
	}

	s := newTestScanner(mock)
	result := s.Scan(context.Background(), defaultCfg(), nil)

	if len(findByID(result.Findings, database.FindingNoDeletionProtect)) != 0 {
		t.Error("should not flag instance with deletion protection")
	}
}

func TestScanReadReplica(t *testing.T) {
	mock := newMockClient()
	mock.instances = []Instance{
		makeInstance("replica-db", "db-f1-micro", "POSTGRES_17", func(i *Instance) {
			i.IsReplica = true
			i.MasterInstanceName = "primary-db"
		}),
	}

	s := newTestScanner(mock)
	result := s.Scan(context.Background(), defaultCfg(), nil)

	hits := findByID(result.Findings, database.FindingUnusedReadReplica)
	if len(hits) != 1 {
		t.Errorf("expected 1 UNUSED_READ_REPLICA finding, got %d", len(hits))
	}
	if hits[0].EstimatedMonthlyWaste <= 0 {
		t.Error("replica finding should have cost estimate")
	}
}

func TestScanNotReplica(t *testing.T) {
	mock := newMockClient()
	mock.instances = []Instance{
		makeInstance("primary-db", "db-f1-micro", "POSTGRES_17"),
	}

	s := newTestScanner(mock)
	result := s.Scan(context.Background(), defaultCfg(), nil)

	if len(findByID(result.Findings, database.FindingUnusedReadReplica)) != 0 {
		t.Error("should not flag non-replica")
	}
}

// --- Error and edge case tests ---

func TestScanListError(t *testing.T) {
	mock := newMockClient()
	mock.err = errors.New("API error")

	s := newTestScanner(mock)
	result := s.Scan(context.Background(), defaultCfg(), nil)

	if len(result.Errors) != 1 {
		t.Errorf("expected 1 error, got %d", len(result.Errors))
	}
}

func TestScanSkipsNonRunnable(t *testing.T) {
	mock := newMockClient()
	mock.instances = []Instance{
		makeInstance("suspended-db", "db-f1-micro", "POSTGRES_17", func(i *Instance) {
			i.State = "SUSPENDED"
			i.DeletionProtection = false // would flag if scanned
		}),
	}

	s := newTestScanner(mock)
	result := s.Scan(context.Background(), defaultCfg(), nil)

	if result.ResourcesScanned != 0 {
		t.Errorf("ResourcesScanned = %d, want 0", result.ResourcesScanned)
	}
	if len(result.Findings) != 0 {
		t.Error("should not scan suspended instances")
	}
}

func TestScanExcludedInstance(t *testing.T) {
	mock := newMockClient()
	mock.instances = []Instance{
		makeInstance("excluded-db", "db-f1-micro", "POSTGRES_17", func(i *Instance) {
			i.DeletionProtection = false
		}),
	}

	cfg := defaultCfg()
	cfg.Exclude.ResourceIDs = map[string]bool{"excluded-db": true}

	s := newTestScanner(mock)
	result := s.Scan(context.Background(), cfg, nil)

	if len(result.Findings) != 0 {
		t.Error("excluded instance should have no findings")
	}
}

func TestScanProgress(t *testing.T) {
	mock := newMockClient()
	mock.instances = []Instance{
		makeInstance("mydb", "db-f1-micro", "POSTGRES_17"),
	}

	var messages []string
	progress := func(p database.ScanProgress) {
		messages = append(messages, p.Message)
	}

	s := newTestScanner(mock)
	s.Scan(context.Background(), defaultCfg(), progress)

	if len(messages) < 3 {
		t.Errorf("expected at least 3 progress messages, got %d", len(messages))
	}
}

func TestScanResourceCount(t *testing.T) {
	mock := newMockClient()
	mock.instances = []Instance{
		makeInstance("db1", "db-f1-micro", "POSTGRES_17"),
		makeInstance("db2", "db-g1-small", "MYSQL_8_0"),
	}

	s := newTestScanner(mock)
	result := s.Scan(context.Background(), defaultCfg(), nil)

	if result.InstancesScanned != 2 {
		t.Errorf("InstancesScanned = %d, want 2", result.InstancesScanned)
	}
	if result.ResourcesScanned != 2 {
		t.Errorf("ResourcesScanned = %d, want 2", result.ResourcesScanned)
	}
}

func TestScanEmptyProject(t *testing.T) {
	mock := newMockClient()

	s := newTestScanner(mock)
	result := s.Scan(context.Background(), defaultCfg(), nil)

	if result.InstancesScanned != 0 {
		t.Errorf("InstancesScanned = %d, want 0", result.InstancesScanned)
	}
	if len(result.Findings) != 0 {
		t.Error("empty project should have no findings")
	}
}

func TestHasPublicAccess(t *testing.T) {
	tests := []struct {
		networks []string
		want     bool
	}{
		{nil, false},
		{[]string{"10.0.0.0/8"}, false},
		{[]string{"0.0.0.0/0"}, true},
		{[]string{"10.0.0.0/8", "0.0.0.0/0"}, true},
	}
	for _, tt := range tests {
		inst := Instance{AuthorizedNetworks: tt.networks}
		if got := hasPublicAccess(inst); got != tt.want {
			t.Errorf("hasPublicAccess(%v) = %v, want %v", tt.networks, got, tt.want)
		}
	}
}

func TestScanOldEngineVersion(t *testing.T) {
	mock := newMockClient()
	mock.instances = []Instance{
		makeInstance("old-db", "db-f1-micro", "POSTGRES_14"), // 3 behind current (17)
	}

	s := newTestScanner(mock)
	result := s.Scan(context.Background(), defaultCfg(), nil)

	hits := findByID(result.Findings, database.FindingOldEngineVersion)
	if len(hits) != 1 {
		t.Errorf("expected 1 OLD_ENGINE_VERSION finding, got %d", len(hits))
	}
}

func TestScanCurrentEngineVersion(t *testing.T) {
	mock := newMockClient()
	mock.instances = []Instance{
		makeInstance("current-db", "db-f1-micro", "POSTGRES_17"), // current
	}

	s := newTestScanner(mock)
	result := s.Scan(context.Background(), defaultCfg(), nil)

	if len(findByID(result.Findings, database.FindingOldEngineVersion)) != 0 {
		t.Error("current version should not be flagged")
	}
}

func TestScanMultipleFindings(t *testing.T) {
	mock := newMockClient()
	mock.instances = []Instance{
		makeInstance("bad-db", "db-f1-micro", "POSTGRES_17", func(i *Instance) {
			i.BackupEnabled = false
			i.DeletionProtection = false
			i.AvailabilityType = "ZONAL"
			i.AuthorizedNetworks = []string{"0.0.0.0/0"}
		}),
	}

	s := newTestScanner(mock)
	result := s.Scan(context.Background(), defaultCfg(), nil)

	// Should have: PUBLIC_ACCESS, NO_AUTOMATED_BACKUPS, NO_MULTI_AZ, NO_DELETION_PROTECTION
	if len(result.Findings) != 4 {
		t.Errorf("expected 4 findings, got %d", len(result.Findings))
		for _, f := range result.Findings {
			t.Logf("  %s: %s", f.ID, f.Message)
		}
	}
}
