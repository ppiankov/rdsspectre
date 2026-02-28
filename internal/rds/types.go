package rds

import (
	"time"

	rdstypes "github.com/aws/aws-sdk-go-v2/service/rds/types"
)

// Instance is a domain type representing an RDS instance.
type Instance struct {
	ID                    string
	ARN                   string
	Class                 string
	Engine                string
	EngineVersion         string
	Status                string
	Region                string
	MultiAZ               bool
	StorageEncrypted      bool
	PubliclyAccessible    bool
	DeletionProtection    bool
	BackupRetentionPeriod int
	AllocatedStorageGB    int
	StorageType           string
	IsReplica             bool
	ReplicaSourceID       string
	ReplicaIDs            []string
	ParameterGroups       []ParameterGroupStatus
	CreateTime            time.Time
}

// ParameterGroupStatus holds parameter group info.
type ParameterGroupStatus struct {
	Name        string
	ApplyStatus string
}

// Snapshot is a domain type representing an RDS manual snapshot.
type Snapshot struct {
	ID                 string
	ARN                string
	InstanceID         string
	Engine             string
	EngineVersion      string
	AllocatedStorageGB int
	CreateTime         time.Time
	Status             string
}

// convertInstance maps SDK type to domain type.
func convertInstance(db rdstypes.DBInstance) Instance {
	inst := Instance{
		ID:                    deref(db.DBInstanceIdentifier),
		ARN:                   deref(db.DBInstanceArn),
		Class:                 deref(db.DBInstanceClass),
		Engine:                deref(db.Engine),
		EngineVersion:         deref(db.EngineVersion),
		Status:                deref(db.DBInstanceStatus),
		MultiAZ:               derefBool(db.MultiAZ),
		StorageEncrypted:      derefBool(db.StorageEncrypted),
		PubliclyAccessible:    derefBool(db.PubliclyAccessible),
		DeletionProtection:    derefBool(db.DeletionProtection),
		BackupRetentionPeriod: derefInt32(db.BackupRetentionPeriod),
		AllocatedStorageGB:    derefInt32(db.AllocatedStorage),
		StorageType:           deref(db.StorageType),
		IsReplica:             db.ReadReplicaSourceDBInstanceIdentifier != nil && *db.ReadReplicaSourceDBInstanceIdentifier != "",
		ReplicaSourceID:       deref(db.ReadReplicaSourceDBInstanceIdentifier),
	}

	inst.ReplicaIDs = append(inst.ReplicaIDs, db.ReadReplicaDBInstanceIdentifiers...)

	for _, pg := range db.DBParameterGroups {
		inst.ParameterGroups = append(inst.ParameterGroups, ParameterGroupStatus{
			Name:        deref(pg.DBParameterGroupName),
			ApplyStatus: deref(pg.ParameterApplyStatus),
		})
	}

	if db.InstanceCreateTime != nil {
		inst.CreateTime = *db.InstanceCreateTime
	}

	return inst
}

// convertSnapshot maps SDK type to domain type.
func convertSnapshot(snap rdstypes.DBSnapshot) Snapshot {
	s := Snapshot{
		ID:                 deref(snap.DBSnapshotIdentifier),
		ARN:                deref(snap.DBSnapshotArn),
		InstanceID:         deref(snap.DBInstanceIdentifier),
		Engine:             deref(snap.Engine),
		EngineVersion:      deref(snap.EngineVersion),
		AllocatedStorageGB: derefInt32(snap.AllocatedStorage),
		Status:             deref(snap.Status),
	}
	if snap.SnapshotCreateTime != nil {
		s.CreateTime = *snap.SnapshotCreateTime
	}
	return s
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func derefBool(b *bool) bool {
	if b == nil {
		return false
	}
	return *b
}

func derefInt32(p *int32) int {
	if p == nil {
		return 0
	}
	return int(*p)
}
