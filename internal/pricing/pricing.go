package pricing

// MonthlyInstanceCost estimates the monthly cost for a database instance.
func MonthlyInstanceCost(provider, instanceClass string) float64 {
	switch provider {
	case "rds":
		hourly, ok := RDSInstanceHourly[instanceClass]
		if !ok {
			hourly = 0.10 // conservative fallback
		}
		return hourly * HoursPerMonth
	case "cloudsql":
		return cloudSQLMonthlyCost(instanceClass)
	default:
		return 0
	}
}

// MonthlyStorageCost estimates monthly storage cost.
func MonthlyStorageCost(provider string, storageGB int64) float64 {
	if storageGB <= 0 {
		return 0
	}
	gb := float64(storageGB)
	switch provider {
	case "rds":
		return gb * RDSStorageCostPerGB
	case "cloudsql":
		return gb * CloudSQLStorageCostPerGB
	default:
		return gb * 0.10
	}
}

// cloudSQLMonthlyCost estimates Cloud SQL cost from machine type.
// Cloud SQL machine types follow the pattern: db-custom-{vcpus}-{memMB}
// or predefined tiers like db-f1-micro, db-g1-small.
func cloudSQLMonthlyCost(tier string) float64 {
	switch tier {
	case "db-f1-micro":
		return 7.67
	case "db-g1-small":
		return 25.55
	default:
		// For custom machine types, use a reasonable default
		return 50.0
	}
}
