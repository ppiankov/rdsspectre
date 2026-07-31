package database

import "testing"

func TestExcludeConfigIsExcluded(t *testing.T) {
	e := ExcludeConfig{ResourceIDs: map[string]bool{"mydb-prod": true}}
	if !e.IsExcluded("mydb-prod") {
		t.Error("expected mydb-prod to be excluded")
	}
	if e.IsExcluded("mydb-dev") {
		t.Error("expected mydb-dev to not be excluded")
	}
}

func TestExcludeConfigIsExcludedNilMap(t *testing.T) {
	var e ExcludeConfig
	if e.IsExcluded("anything") {
		t.Error("nil ResourceIDs should exclude nothing")
	}
}

func TestMatchesExcludedTagsExactMatch(t *testing.T) {
	e := ExcludeConfig{Tags: map[string]string{"env": "temporary"}}
	if !e.MatchesExcludedTags(map[string]string{"env": "temporary"}) {
		t.Error("expected exact key=value match to exclude")
	}
}

func TestMatchesExcludedTagsKeyOnlyWildcard(t *testing.T) {
	e := ExcludeConfig{Tags: map[string]string{"temporary": ""}}
	if !e.MatchesExcludedTags(map[string]string{"temporary": "anything"}) {
		t.Error("empty configured value should match any value for that key")
	}
}

func TestMatchesExcludedTagsNoMatch(t *testing.T) {
	e := ExcludeConfig{Tags: map[string]string{"env": "temporary"}}
	if e.MatchesExcludedTags(map[string]string{"env": "production"}) {
		t.Error("mismatched value should not exclude")
	}
	if e.MatchesExcludedTags(map[string]string{"other": "temporary"}) {
		t.Error("missing key should not exclude")
	}
}

func TestMatchesExcludedTagsEmptyRules(t *testing.T) {
	var e ExcludeConfig
	if e.MatchesExcludedTags(map[string]string{"env": "production"}) {
		t.Error("no configured rules should never exclude")
	}
}

func TestReportProgressNilCallback(t *testing.T) {
	// Must not panic when progress is nil.
	ReportProgress(nil, "rds", "us-east-1", "scanning")
}

func TestReportProgressInvokesCallback(t *testing.T) {
	var got ScanProgress
	ReportProgress(func(p ScanProgress) { got = p }, "cloudsql", "my-project", "listing instances")
	if got.Scanner != "cloudsql" || got.Region != "my-project" || got.Message != "listing instances" {
		t.Errorf("unexpected progress: %+v", got)
	}
}

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
