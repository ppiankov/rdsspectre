package rds

import "testing"

func TestVersionsBehind(t *testing.T) {
	tests := []struct {
		engine  string
		version string
		want    int
	}{
		{"postgres", "17.2", 0},
		{"postgres", "16.4", 1},
		{"postgres", "13.4", 4},
		{"mysql", "8.0.35", 0},
		{"mysql", "5.7.44", 3},
		{"aurora-mysql", "3.06.0", 0},
		{"aurora-mysql", "1.19.6", 2},
		{"mariadb", "11.4.0", 0},
		{"mariadb", "10.6.0", 1},
		{"unknown-engine", "1.0", 0},
		{"postgres", "", 0},
	}

	for _, tt := range tests {
		got := VersionsBehind(tt.engine, tt.version)
		if got != tt.want {
			t.Errorf("VersionsBehind(%q, %q) = %d, want %d", tt.engine, tt.version, got, tt.want)
		}
	}
}

func TestVersionsBehindGCPFormat(t *testing.T) {
	// GCP POSTGRES_14: current=17 (postgres family), parsed=14, diff=3
	got := VersionsBehind("POSTGRES_14", "")
	if got != 3 {
		t.Errorf("POSTGRES_14 should be 3 behind, got %d", got)
	}
	// MYSQL_5_7: current=8 (mysql family), parsed=5, diff=3
	got = VersionsBehind("MYSQL_5_7", "")
	if got != 3 {
		t.Errorf("MYSQL_5_7 should be 3 behind, got %d", got)
	}
	// POSTGRES_17: current=17, parsed=17, diff=0
	got = VersionsBehind("POSTGRES_17", "")
	if got != 0 {
		t.Errorf("POSTGRES_17 should be current, got %d", got)
	}
	// MYSQL_8_0: current=8, parsed=8, diff=0
	got = VersionsBehind("MYSQL_8_0", "")
	if got != 0 {
		t.Errorf("MYSQL_8_0 should be current, got %d", got)
	}
}

func TestVersionsBehindNewerThanCurrent(t *testing.T) {
	// If somehow the instance version is newer than our known current, return 0
	got := VersionsBehind("postgres", "99.0")
	if got != 0 {
		t.Errorf("newer than current should return 0, got %d", got)
	}
}

func TestParseMajorVersion(t *testing.T) {
	tests := []struct {
		engine  string
		version string
		want    int
	}{
		{"postgres", "17.2", 17},
		{"mysql", "8.0.35", 8},
		{"aurora-mysql", "3.06.0", 3},
		{"postgres", "", 0},
		{"postgres", "abc", 0},
		{"MYSQL_8_0", "", 8},
		{"POSTGRES_14", "", 14},
		{"SQLSERVER_2019", "", 2019}, // splits on _ and parses "2019"
	}

	for _, tt := range tests {
		got := parseMajorVersion(tt.engine, tt.version)
		if got != tt.want {
			t.Errorf("parseMajorVersion(%q, %q) = %d, want %d", tt.engine, tt.version, got, tt.want)
		}
	}
}
