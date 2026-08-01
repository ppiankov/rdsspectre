# rdsspectre

Managed database waste and security auditor for AWS RDS and GCP Cloud SQL.

## Install

```
brew install ppiankov/tap/rdsspectre
```

Or via Go:

```
go install github.com/ppiankov/rdsspectre/cmd/rdsspectre@latest
```

## Commands

### rdsspectre aws

Scans AWS RDS instances and manual snapshots for waste and security findings.

**Flags:**
- `--region string` — AWS region (default: from AWS config)
- `--profile string` — AWS profile name
- `--idle-days int` — days of low activity to flag as idle (default 14)
- `--stale-days int` — snapshot age threshold in days (default 90)
- `--cpu-threshold float` — flag oversized if p95 CPU is below this percent (default 20.0)
- `--idle-cpu float` — flag idle if avg CPU is below this percent (default 5.0)
- `--metric-days int` — CloudWatch metric lookback period in days (default 14)
- `--format string` — output format: `text` (default), `sarif`, `spectrehub`, or `--format json` for the `spectre/v1` envelope
- `-o, --output string` — output file path (default: stdout)
- `--min-monthly-cost float` — minimum monthly cost to report, in USD (default 0.10)
- `--no-progress` — disable progress output
- `--timeout duration` — scan timeout (default 10m)
- `--exclude-tags strings` — exclude resources by tag, `Key=Value`, comma-separated

**JSON output** (`--format json`, `spectre/v1` schema — `gcp` uses the same envelope):
```json
{
  "schema": "spectre/v1",
  "tool": "rdsspectre",
  "version": "1.0.0",
  "timestamp": "2026-08-01T00:00:00Z",
  "target": {
    "type": "rds",
    "uri_hash": "sha256:abc123"
  },
  "config": {
    "provider": "aws",
    "regions": ["us-east-1"],
    "idle_days": 14,
    "stale_days": 90,
    "cpu_threshold": 20.0,
    "min_monthly_cost": 0.10
  },
  "findings": [
    {
      "id": "IDLE_INSTANCE",
      "severity": "high",
      "resource_type": "instance",
      "resource_id": "mydb-prod",
      "region": "us-east-1",
      "message": "Instance idle for 14 days (avg CPU 2.1%, 0 connections)",
      "estimated_monthly_waste": 124.10
    }
  ],
  "summary": {
    "total_findings": 1,
    "instances_scanned": 5,
    "resources_scanned": 5,
    "total_monthly_waste": 124.10
  },
  "errors": []
}
```

**Exit codes:**
- 0: scan completed — a clean account and a scan with findings both exit 0; check `findings`/`summary`, not the exit code, for results
- 1: scan failed (authentication, network, invalid flags/config, or output-file write error)

### rdsspectre gcp

Scans GCP Cloud SQL instances for waste and security findings.

**Flags:**
- `--project string` — GCP project ID (required)
- `--format string` — output format: `text` (default), `sarif`, `spectrehub`, or `--format json` for the same `spectre/v1` envelope as `aws` (see above)
- `-o, --output string` — output file path (default: stdout)
- `--min-monthly-cost float` — minimum monthly cost to report, in USD (default 0.10)
- `--no-progress` — disable progress output
- `--timeout duration` — scan timeout (default 10m)
- `--exclude-tags strings` — exclude resources by label, `Key=Value`, comma-separated

**Exit codes:** same as `aws` above.

### rdsspectre init

Writes a sample `.rdsspectre.yaml` config and a read-only IAM policy
(`rdsspectre-policy.json`) to the current directory.

**Flags:**
- `--force` — overwrite existing files

**Exit codes:**
- 0: files written, or already present and left unchanged (a message is printed; use `--force` to overwrite)

### rdsspectre version

Prints version, commit, and build date. No flags.

## Handoffs

- Output: `spectre/v1` JSON envelope. Next: `spectrehub collect --tool rdsspectre` for aggregation across scanners.
- Output: SARIF. Next: CI security-gate or code-scanning ingestion.
- Refused questions: how to fix a finding, whether to remediate, risk-acceptance decisions — rdsspectre reports, it does not advise on remediation policy.

## What this does NOT do

- Does not modify, delete, or resize any RDS instance, snapshot, or Cloud SQL instance — strictly read-only
- Does not execute SQL queries or profile database performance
- Does not persist findings between runs or maintain a findings database

## Failure Modes

- Authentication failure (missing/expired AWS or GCP credentials): exits 1 before any scanning begins. Distrust: no findings are produced. Safe fallback: fix credentials and re-run; nothing is cached.
- Network/API error on the initial list call: exits 1. Distrust: no findings for that run.
- Per-resource API error during a scan (e.g. one region's metrics unavailable): the scan still completes and exits 0, with the problem surfaced in the `errors` array. Distrust: `summary` counts are incomplete whenever `errors` is non-empty.

## Parsing examples

```bash
rdsspectre aws --region us-east-1 --format json | jq '.summary'
rdsspectre aws --region us-east-1 --format json | jq '.findings[] | select(.severity == "critical")'
rdsspectre gcp --project my-project --format json | jq '.errors'
```

---

This tool follows the [Agent-Native CLI Convention](https://ancc.dev). Validate with: `ancc validate .`
