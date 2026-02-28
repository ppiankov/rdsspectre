package rds

import (
	"strconv"
	"strings"
)

// CurrentMajorVersions maps engine names to the current major version for that engine family.
// GCP Cloud SQL entries (uppercase) map to the same current version as their RDS counterparts,
// so VersionsBehind correctly calculates how far behind a GCP instance is.
var CurrentMajorVersions = map[string]int{
	// AWS RDS engines
	"mysql":             8,
	"postgres":          17,
	"mariadb":           11,
	"oracle-ee":         19,
	"oracle-se2":        19,
	"oracle-se2-cdb":    19,
	"sqlserver-ee":      16,
	"sqlserver-se":      16,
	"sqlserver-ex":      16,
	"sqlserver-web":     16,
	"aurora-mysql":      3,
	"aurora-postgresql": 16,
	// GCP Cloud SQL engines — value is the CURRENT version for that engine family
	"MYSQL_8_0":               8,  // mysql current = 8
	"MYSQL_5_7":               8,  // mysql current = 8
	"POSTGRES_17":             17, // postgres current = 17
	"POSTGRES_16":             17, // postgres current = 17
	"POSTGRES_15":             17, // postgres current = 17
	"POSTGRES_14":             17, // postgres current = 17
	"SQLSERVER_2022_STANDARD": 16, // sqlserver current = 16
	"SQLSERVER_2019_STANDARD": 16, // sqlserver current = 16
}

// VersionsBehind returns how many major versions behind the instance is.
// Returns 0 if the engine is unknown or the version is current.
func VersionsBehind(engine, versionStr string) int {
	current, ok := CurrentMajorVersions[engine]
	if !ok {
		return 0
	}

	major := parseMajorVersion(engine, versionStr)
	if major <= 0 {
		return 0
	}

	diff := current - major
	if diff < 0 {
		return 0
	}
	return diff
}

// parseMajorVersion extracts the major version number from a version string.
func parseMajorVersion(engine, versionStr string) int {
	// GCP Cloud SQL versions embed the version in the engine name (e.g., MYSQL_8_0)
	if strings.Contains(engine, "_") {
		parts := strings.Split(engine, "_")
		if len(parts) >= 2 {
			v, err := strconv.Atoi(parts[1])
			if err == nil {
				return v
			}
		}
	}

	// Standard version string: "8.0.35", "17.2", "3.06.0"
	parts := strings.SplitN(versionStr, ".", 2)
	if len(parts) == 0 {
		return 0
	}
	v, err := strconv.Atoi(parts[0])
	if err != nil {
		return 0
	}
	return v
}
