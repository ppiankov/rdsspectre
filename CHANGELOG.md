# Changelog

## [Unreleased]

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
