package cloudsql

import (
	"context"
	"fmt"
	"time"
)

type mockCloudSQLClient struct {
	instances []Instance
	err       error
}

func newMockClient() *mockCloudSQLClient {
	return &mockCloudSQLClient{}
}

func (m *mockCloudSQLClient) ListInstances(_ context.Context, _ string) ([]Instance, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.instances, nil
}

// makeInstance creates a test Cloud SQL instance with sensible defaults and functional options.
func makeInstance(name, tier, dbVersion string, opts ...func(*Instance)) Instance {
	inst := Instance{
		Name:               name,
		Project:            "test-project",
		DatabaseVersion:    dbVersion,
		State:              "RUNNABLE",
		Tier:               tier,
		Region:             "us-central1",
		AvailabilityType:   "REGIONAL",
		DataDiskSizeGB:     100,
		DataDiskType:       "PD_SSD",
		BackupEnabled:      true,
		DeletionProtection: true,
		IPv4Enabled:        false,
		IsReplica:          false,
		CreateTime:         time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
		SelfLink:           fmt.Sprintf("https://sqladmin.googleapis.com/sql/v1beta4/projects/test-project/instances/%s", name),
	}
	for _, opt := range opts {
		opt(&inst)
	}
	return inst
}
