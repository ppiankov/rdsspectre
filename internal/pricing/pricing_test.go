package pricing

import (
	"math"
	"testing"
)

func TestMonthlyInstanceCostRDS(t *testing.T) {
	cost := MonthlyInstanceCost("rds", "db.t3.micro")
	expected := 0.017 * HoursPerMonth
	if math.Abs(cost-expected) > 0.01 {
		t.Errorf("cost = $%.2f, want ~$%.2f", cost, expected)
	}
}

func TestMonthlyInstanceCostRDSUnknown(t *testing.T) {
	cost := MonthlyInstanceCost("rds", "db.unknown.type")
	expected := 0.10 * HoursPerMonth
	if math.Abs(cost-expected) > 0.01 {
		t.Errorf("unknown instance cost = $%.2f, want ~$%.2f (fallback)", cost, expected)
	}
}

func TestMonthlyInstanceCostCloudSQL(t *testing.T) {
	cost := MonthlyInstanceCost("cloudsql", "db-f1-micro")
	if cost != 7.67 {
		t.Errorf("cost = $%.2f, want $7.67", cost)
	}
}

func TestMonthlyInstanceCostUnknownProvider(t *testing.T) {
	cost := MonthlyInstanceCost("azure", "Standard_D2s_v3")
	if cost != 0 {
		t.Errorf("unknown provider cost = $%.2f, want $0", cost)
	}
}

func TestMonthlyStorageCostRDS(t *testing.T) {
	cost := MonthlyStorageCost("rds", 100)
	expected := 100.0 * RDSStorageCostPerGB
	if math.Abs(cost-expected) > 0.01 {
		t.Errorf("cost = $%.2f, want ~$%.2f", cost, expected)
	}
}

func TestMonthlyStorageCostCloudSQL(t *testing.T) {
	cost := MonthlyStorageCost("cloudsql", 50)
	expected := 50.0 * CloudSQLStorageCostPerGB
	if math.Abs(cost-expected) > 0.01 {
		t.Errorf("cost = $%.2f, want ~$%.2f", cost, expected)
	}
}

func TestMonthlyStorageCostZero(t *testing.T) {
	cost := MonthlyStorageCost("rds", 0)
	if cost != 0 {
		t.Errorf("zero storage cost = $%.2f, want $0", cost)
	}
}

func TestMonthlyStorageCostNegative(t *testing.T) {
	cost := MonthlyStorageCost("rds", -10)
	if cost != 0 {
		t.Errorf("negative storage cost = $%.2f, want $0", cost)
	}
}

func TestMonthlyStorageCostUnknownProvider(t *testing.T) {
	cost := MonthlyStorageCost("azure", 100)
	expected := 100.0 * 0.10
	if math.Abs(cost-expected) > 0.01 {
		t.Errorf("unknown provider storage = $%.2f, want ~$%.2f", cost, expected)
	}
}

func TestCloudSQLSmall(t *testing.T) {
	cost := MonthlyInstanceCost("cloudsql", "db-g1-small")
	if cost != 25.55 {
		t.Errorf("cost = $%.2f, want $25.55", cost)
	}
}

func TestCloudSQLCustom(t *testing.T) {
	cost := MonthlyInstanceCost("cloudsql", "db-custom-4-15360")
	if cost != 50.0 {
		t.Errorf("cost = $%.2f, want $50.00", cost)
	}
}
