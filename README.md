# rdsspectre

[![CI](https://github.com/ppiankov/rdsspectre/actions/workflows/ci.yml/badge.svg)](https://github.com/ppiankov/rdsspectre/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/ppiankov/rdsspectre)](https://goreportcard.com/report/github.com/ppiankov/rdsspectre)

**rdsspectre** — Managed database waste and security auditor for RDS and Cloud SQL. Part of [SpectreHub](https://github.com/ppiankov/spectrehub).

## What it is

- Scans AWS RDS and GCP Cloud SQL for idle, oversized, and misconfigured instances
- Detects unencrypted databases, public accessibility, and missing backups
- Estimates monthly waste in USD per finding
- Generates IAM policy and config file via init command
- Outputs text, JSON, SARIF, and SpectreHub formats

## What it is NOT

- Not a database query tool or performance profiler
- Not a migration or modification tool — strictly read-only
- Not a replacement for Trusted Advisor or GCP Recommender

## Quick start

### Homebrew

```sh
brew tap ppiankov/tap
brew install rdsspectre
```

### From source

```sh
git clone https://github.com/ppiankov/rdsspectre.git
cd rdsspectre
make build
```

### Usage

```sh
rdsspectre aws --region us-east-1 --format json
```

## CLI commands

| Command | Description |
|---------|-------------|
| `rdsspectre aws` | Scan AWS RDS instances |
| `rdsspectre gcp` | Scan GCP Cloud SQL instances |
| `rdsspectre init` | Generate IAM policy and config file |
| `rdsspectre version` | Print version |

## SpectreHub integration

rdsspectre feeds managed database waste findings into [SpectreHub](https://github.com/ppiankov/spectrehub) for unified visibility across your infrastructure.

```sh
spectrehub collect --tool rdsspectre
```

## Safety

rdsspectre operates in **read-only mode**. It inspects and reports — never modifies, deletes, or alters your databases.

## License

MIT — see [LICENSE](LICENSE).

---

Built by [Obsta Labs](https://github.com/ppiankov)
