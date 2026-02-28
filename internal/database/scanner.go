package database

import "context"

// DatabaseScanner is the interface implemented by all cloud-provider scanners.
type DatabaseScanner interface {
	Scan(ctx context.Context, cfg ScanConfig, progress func(ScanProgress)) *ScanResult
}
