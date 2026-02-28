package database

import "testing"

func TestSeverityConstants(t *testing.T) {
	if SeverityCritical != "critical" {
		t.Error("SeverityCritical mismatch")
	}
	if SeverityHigh != "high" {
		t.Error("SeverityHigh mismatch")
	}
	if SeverityMedium != "medium" {
		t.Error("SeverityMedium mismatch")
	}
	if SeverityLow != "low" {
		t.Error("SeverityLow mismatch")
	}
}

func TestResourceTypeConstants(t *testing.T) {
	if ResourceInstance != "instance" {
		t.Error("ResourceInstance mismatch")
	}
	if ResourceSnapshot != "snapshot" {
		t.Error("ResourceSnapshot mismatch")
	}
	if ResourceReplica != "replica" {
		t.Error("ResourceReplica mismatch")
	}
}

func TestFindingIDConstants(t *testing.T) {
	ids := []FindingID{
		FindingIdleInstance, FindingOversizedInstance, FindingUnencryptedStorage,
		FindingPublicAccess, FindingNoAutomatedBackups, FindingStaleSnapshot,
		FindingUnusedReadReplica, FindingNoMultiAZ, FindingOldEngineVersion,
		FindingNoDeletionProtect, FindingParameterGroupDrift,
	}
	if len(ids) != 11 {
		t.Errorf("expected 11 finding IDs, got %d", len(ids))
	}
	seen := make(map[FindingID]bool)
	for _, id := range ids {
		if seen[id] {
			t.Errorf("duplicate FindingID: %s", id)
		}
		seen[id] = true
	}
}
