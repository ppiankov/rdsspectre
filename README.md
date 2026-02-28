# rdsspectre

Managed database waste and security auditor for AWS RDS and GCP Cloud SQL.

## What it is

A read-only CLI tool that scans managed database instances for idle, oversized, unencrypted, publicly accessible, and misconfigured databases. Each finding includes severity and estimated monthly waste in USD.

## What it is NOT

- Not a database query tool or performance profiler
- Not a migration or modification tool — strictly read-only
- Not a replacement for AWS Trusted Advisor or GCP Recommender — deeper, database-specific checks

## Quick Start

```bash
# Install
go install github.com/ppiankov/rdsspectre/cmd/rdsspectre@latest

# Generate config and IAM policy
rdsspectre init

# Scan AWS RDS
rdsspectre aws --region us-east-1

# Scan GCP Cloud SQL
rdsspectre gcp --project my-project
```

## Usage

```bash
# AWS RDS scan with custom thresholds
rdsspectre aws --region us-east-1 --idle-days 7 --cpu-threshold 15 --format json

# GCP Cloud SQL scan
rdsspectre gcp --project my-project --format json

# Output to file
rdsspectre aws --region us-east-1 -o report.json --format json

# Exclude specific instances
rdsspectre aws --exclude-tags env=production
rdsspectre gcp --project my-project --exclude-tags env=production
```

## Finding Types

| Finding | Severity | AWS | GCP | Description |
|---------|----------|-----|-----|-------------|
| IDLE_INSTANCE | high | yes | — | CPU < 5%, zero connections over N days |
| OVERSIZED_INSTANCE | high | yes | — | CPU p95 < 20% with active connections |
| UNENCRYPTED_STORAGE | critical | yes | — | Storage encryption disabled |
| PUBLIC_ACCESS | critical | yes | yes | Instance publicly accessible |
| NO_AUTOMATED_BACKUPS | critical | yes | yes | Backup retention period is zero |
| STALE_SNAPSHOT | medium | yes | — | Manual snapshot older than threshold |
| UNUSED_READ_REPLICA | high | yes | yes | Read replica with zero connections |
| NO_MULTI_AZ | high | yes | yes | Single-AZ / ZONAL deployment |
| OLD_ENGINE_VERSION | medium | yes | yes | 2+ major versions behind current |
| NO_DELETION_PROTECTION | medium | yes | yes | Deletion protection disabled |
| PARAMETER_GROUP_DRIFT | low | yes | — | Non-default parameter group |

## Output Formats

- `text` — human-readable table (default)
- `json` — spectre/v1 JSON envelope
- `sarif` — SARIF v2.1.0 for CI integration
- `spectrehub` — SpectreHub envelope

## License

MIT
