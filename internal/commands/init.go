package commands

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var initFlags struct {
	force bool
}

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Generate sample config and IAM policy",
	RunE:  runInit,
}

func init() {
	initCmd.Flags().BoolVar(&initFlags.force, "force", false, "Overwrite existing files")
}

func runInit(_ *cobra.Command, _ []string) error {
	wrote := false

	ok, err := writeIfNotExists(".rdsspectre.yaml", sampleConfig, initFlags.force)
	if err != nil {
		return err
	}
	if ok {
		wrote = true
		fmt.Println("Created .rdsspectre.yaml")
	}

	ok, err = writeIfNotExists("rdsspectre-policy.json", sampleIAMPolicy, initFlags.force)
	if err != nil {
		return err
	}
	if ok {
		wrote = true
		fmt.Println("Created rdsspectre-policy.json")
	}

	if !wrote {
		fmt.Println("Files already exist. Use --force to overwrite.")
	}

	return nil
}

func writeIfNotExists(path, content string, force bool) (bool, error) {
	if !force {
		if _, err := os.Stat(path); err == nil {
			return false, nil
		}
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		return false, fmt.Errorf("write %s: %w", path, err)
	}
	return true, nil
}

const sampleConfig = `# rdsspectre configuration
# provider: aws or gcp
provider: aws

# AWS regions to scan (default: current region)
regions:
  - us-east-1

# idle_days: flag instances idle for this many days (default: 14)
idle_days: 14

# stale_days: flag manual snapshots older than this (default: 90)
stale_days: 90

# cpu_threshold: flag oversized if p95 CPU below this (default: 20)
cpu_threshold: 20

# metric_days: CloudWatch lookback period in days (default: 14)
metric_days: 14

# min_monthly_cost: only report findings above this threshold (default: 0.10)
min_monthly_cost: 0.10

# format: text, json, sarif, spectrehub
format: text

# timeout: scan timeout (default: 10m)
timeout: "10m"

# exclude specific resources
exclude:
  resource_ids: []
  tags: []
`

const sampleIAMPolicy = `{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "RdsSpectreReadOnly",
      "Effect": "Allow",
      "Action": [
        "rds:DescribeDBInstances",
        "rds:DescribeDBSnapshots",
        "rds:DescribeDBClusters",
        "rds:ListTagsForResource",
        "cloudwatch:GetMetricStatistics",
        "sts:GetCallerIdentity"
      ],
      "Resource": "*"
    }
  ]
}
`
