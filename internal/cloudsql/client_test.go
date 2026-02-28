package cloudsql

import (
	"testing"

	sqladmin "google.golang.org/api/sqladmin/v1beta4"
)

func TestConvertInstanceBasic(t *testing.T) {
	db := &sqladmin.DatabaseInstance{
		Name:            "mydb",
		Project:         "my-project",
		DatabaseVersion: "POSTGRES_15",
		State:           "RUNNABLE",
		Region:          "us-central1",
		InstanceType:    "CLOUD_SQL_INSTANCE",
		SelfLink:        "https://sqladmin.googleapis.com/sql/v1beta4/projects/my-project/instances/mydb",
		CreateTime:      "2025-06-15T10:30:00.000Z",
		Settings: &sqladmin.Settings{
			Tier:                      "db-custom-4-15360",
			AvailabilityType:          "REGIONAL",
			DataDiskSizeGb:            100,
			DataDiskType:              "PD_SSD",
			DeletionProtectionEnabled: true,
			BackupConfiguration:       &sqladmin.BackupConfiguration{Enabled: true},
			IpConfiguration: &sqladmin.IpConfiguration{
				Ipv4Enabled: true,
				AuthorizedNetworks: []*sqladmin.AclEntry{
					{Value: "10.0.0.0/8"},
					{Value: "172.16.0.0/12"},
				},
			},
		},
	}

	inst := convertInstance(db)

	if inst.Name != "mydb" {
		t.Errorf("Name = %q, want mydb", inst.Name)
	}
	if inst.Project != "my-project" {
		t.Errorf("Project = %q, want my-project", inst.Project)
	}
	if inst.DatabaseVersion != "POSTGRES_15" {
		t.Errorf("DatabaseVersion = %q, want POSTGRES_15", inst.DatabaseVersion)
	}
	if inst.State != "RUNNABLE" {
		t.Errorf("State = %q, want RUNNABLE", inst.State)
	}
	if inst.Tier != "db-custom-4-15360" {
		t.Errorf("Tier = %q, want db-custom-4-15360", inst.Tier)
	}
	if inst.AvailabilityType != "REGIONAL" {
		t.Errorf("AvailabilityType = %q, want REGIONAL", inst.AvailabilityType)
	}
	if inst.DataDiskSizeGB != 100 {
		t.Errorf("DataDiskSizeGB = %d, want 100", inst.DataDiskSizeGB)
	}
	if !inst.BackupEnabled {
		t.Error("BackupEnabled should be true")
	}
	if !inst.DeletionProtection {
		t.Error("DeletionProtection should be true")
	}
	if !inst.IPv4Enabled {
		t.Error("IPv4Enabled should be true")
	}
	if len(inst.AuthorizedNetworks) != 2 {
		t.Errorf("AuthorizedNetworks = %d, want 2", len(inst.AuthorizedNetworks))
	}
	if inst.IsReplica {
		t.Error("IsReplica should be false")
	}
	if inst.CreateTime.IsZero() {
		t.Error("CreateTime should be parsed")
	}
}

func TestConvertInstanceReplica(t *testing.T) {
	db := &sqladmin.DatabaseInstance{
		Name:               "replica-db",
		Project:            "my-project",
		DatabaseVersion:    "MYSQL_8_0",
		State:              "RUNNABLE",
		InstanceType:       "READ_REPLICA_INSTANCE",
		MasterInstanceName: "primary-db",
		Region:             "us-central1",
	}

	inst := convertInstance(db)

	if !inst.IsReplica {
		t.Error("IsReplica should be true for READ_REPLICA_INSTANCE")
	}
	if inst.MasterInstanceName != "primary-db" {
		t.Errorf("MasterInstanceName = %q, want primary-db", inst.MasterInstanceName)
	}
}

func TestConvertInstanceNilSettings(t *testing.T) {
	db := &sqladmin.DatabaseInstance{
		Name:            "bare-db",
		Project:         "my-project",
		DatabaseVersion: "POSTGRES_14",
		State:           "RUNNABLE",
		Region:          "us-central1",
	}

	inst := convertInstance(db)

	if inst.Tier != "" {
		t.Errorf("Tier should be empty, got %q", inst.Tier)
	}
	if inst.BackupEnabled {
		t.Error("BackupEnabled should be false without settings")
	}
}

func TestConvertInstanceNilBackupConfig(t *testing.T) {
	db := &sqladmin.DatabaseInstance{
		Name:            "no-backup-db",
		Project:         "my-project",
		DatabaseVersion: "POSTGRES_15",
		State:           "RUNNABLE",
		Region:          "us-central1",
		Settings: &sqladmin.Settings{
			Tier:             "db-f1-micro",
			AvailabilityType: "ZONAL",
		},
	}

	inst := convertInstance(db)

	if inst.BackupEnabled {
		t.Error("BackupEnabled should be false without backup config")
	}
	if inst.IPv4Enabled {
		t.Error("IPv4Enabled should be false without ip config")
	}
}

func TestConvertInstanceInvalidCreateTime(t *testing.T) {
	db := &sqladmin.DatabaseInstance{
		Name:            "bad-time-db",
		Project:         "my-project",
		DatabaseVersion: "POSTGRES_15",
		State:           "RUNNABLE",
		Region:          "us-central1",
		CreateTime:      "not-a-time",
	}

	inst := convertInstance(db)

	if !inst.CreateTime.IsZero() {
		t.Error("CreateTime should be zero for invalid time")
	}
}

func TestConvertInstanceEmptyCreateTime(t *testing.T) {
	db := &sqladmin.DatabaseInstance{
		Name:            "no-time-db",
		Project:         "my-project",
		DatabaseVersion: "POSTGRES_15",
		State:           "RUNNABLE",
		Region:          "us-central1",
	}

	inst := convertInstance(db)

	if !inst.CreateTime.IsZero() {
		t.Error("CreateTime should be zero for empty time")
	}
}
