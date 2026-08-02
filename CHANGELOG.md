# Changelog

## [Unreleased]

## [0.1.3] - 2026-08-02

### Added
- Evidence-graded cost findings: every `IDLE_INSTANCE` and `OVERSIZED_INSTANCE`
  finding now carries a `confidence` field (`confident` or `needs_review`) and
  optional `countersignals` explaining why confidence was downgraded
- Summary now splits monthly waste into `confident_monthly_waste` and
  `needs_review_monthly_waste` so the operator sees at a glance how much of the
  headline number is actionable
- IOPS-based idle detection: `IDLE_INSTANCE` now flags instances with near-zero
  total IOPS even when connection pools hold connections open — the previous
  `TotalConns == 0` rule structurally never fired with pooled connections

### Fixed
- `OVERSIZED_INSTANCE` grading uses swap GROWTH (not swap presence) as a
  memory-pressure countersignal; flat swap from Linux's boot-time page parking
  no longer reads as pressure
- Write-IOPS countersignal added to `OVERSIZED_INSTANCE`: a low-CPU instance
  sustaining heavy writes is graded `needs_review` because burstable instance
  classes scale EBS bandwidth with size
- `DatabaseConnections` metric changed from Sum to Average so reported
  connection counts are meaningful (e.g. 7 instead of 134305)
- SpectreHub README links now point to spectrehub.dev; retired Go Report Card
  badge removed

## [0.1.2] - 2026-08-01

### Fixed
- Windows build+test coverage in CI, plus a README Windows quick-start
- Config keys (`provider`, `timeout`, `exclude.tags`) that were parsed but never
  wired to scan behavior now actually take effect
- Explicit CLI flags now correctly override config file values when the flag
  is set to its own default (e.g. `--idle-days=14`)
- Text reporter now sorts findings by severity instead of scan order
- GCP unused-read-replica finding no longer reports a confirmed monthly-waste
  figure without a real usage signal
- `selectReporter`'s output file handle is now closed, fixing a Windows CI
  failure where an open handle blocked temp-directory cleanup
- `docs/SKILL.md` described a nonexistent `scan` command and flags; rewritten
  to match the real CLI (`aws`/`gcp`/`init`/`version`, real flags, real
  `spectre/v1` JSON schema, real exit codes)

### Changed
- Deduplicated exclusion-check and progress-reporting logic shared by the
  AWS and GCP scanners

## [0.1.1] - 2026-02-28

### Fixed
- SpectreHub reporter now uses the `spectre/v1` schema

## [0.1.0] - 2026-02-28

### Added
- AWS RDS scanner with 11 finding types
- GCP Cloud SQL scanner with 6 config-based findings
- CloudWatch metric integration for idle and oversized detection
- Text, JSON, SARIF, and SpectreHub output formats
- Config file support (.rdsspectre.yaml)
- IAM policy generator (rdsspectre init)
