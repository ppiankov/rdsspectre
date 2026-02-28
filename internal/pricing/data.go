package pricing

// RDSInstanceHourly contains on-demand hourly rates for common RDS instance classes (us-east-1 baseline).
var RDSInstanceHourly = map[string]float64{
	"db.t3.micro":    0.017,
	"db.t3.small":    0.034,
	"db.t3.medium":   0.068,
	"db.t3.large":    0.136,
	"db.t3.xlarge":   0.272,
	"db.t3.2xlarge":  0.544,
	"db.t4g.micro":   0.016,
	"db.t4g.small":   0.032,
	"db.t4g.medium":  0.065,
	"db.t4g.large":   0.129,
	"db.t4g.xlarge":  0.258,
	"db.t4g.2xlarge": 0.516,
	"db.r5.large":    0.240,
	"db.r5.xlarge":   0.480,
	"db.r5.2xlarge":  0.960,
	"db.r5.4xlarge":  1.920,
	"db.r6g.large":   0.218,
	"db.r6g.xlarge":  0.435,
	"db.r6g.2xlarge": 0.870,
	"db.m5.large":    0.171,
	"db.m5.xlarge":   0.342,
	"db.m5.2xlarge":  0.684,
	"db.m6g.large":   0.155,
	"db.m6g.xlarge":  0.310,
	"db.m6g.2xlarge": 0.620,
}

// RDSStorageCostPerGB is the monthly cost per GB for gp3 storage.
const RDSStorageCostPerGB = 0.115

// CloudSQLStorageCostPerGB is the monthly cost per GB for Cloud SQL SSD storage.
const CloudSQLStorageCostPerGB = 0.170

// HoursPerMonth is the average number of hours in a month.
const HoursPerMonth = 730.0

// CloudSQLVCPUHourly is the hourly cost per vCPU for Cloud SQL.
const CloudSQLVCPUHourly = 0.0413

// CloudSQLMemGBHourly is the hourly cost per GB of RAM for Cloud SQL.
const CloudSQLMemGBHourly = 0.0070
