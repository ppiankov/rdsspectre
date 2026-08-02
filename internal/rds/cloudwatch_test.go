package rds

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	rdstypes "github.com/aws/aws-sdk-go-v2/service/rds/types"
)

// WO-7: exercises FetchTags.
func TestFetchTags(t *testing.T) {
	mock := newMockRDSClient()
	mock.tagsForARN["arn:aws:rds:us-east-1:123456789012:db:mydb"] = []rdstypes.Tag{
		{Key: aws.String("env"), Value: aws.String("production")},
		{Key: aws.String("team"), Value: aws.String("platform")},
	}

	tags, err := FetchTags(context.Background(), mock, "arn:aws:rds:us-east-1:123456789012:db:mydb")
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if tags["env"] != "production" || tags["team"] != "platform" {
		t.Errorf("unexpected tags: %+v", tags)
	}
}

// WO-7: exercises FetchTags.
func TestFetchTagsError(t *testing.T) {
	mock := newMockRDSClient()
	mock.listTagsErr = errors.New("boom")

	_, err := FetchTags(context.Background(), mock, "arn:aws:rds:us-east-1:123456789012:db:mydb")
	if err == nil {
		t.Error("expected error to propagate")
	}
}

func TestFetchInstanceMetricsIdle(t *testing.T) {
	cw := newMockCWClient()
	cw.metrics["CPUUtilization"] = makeCPUDatapoints(2.0, 4.0, 14)
	cw.metrics["DatabaseConnections"] = makeConnDatapoints(0)

	stats, err := FetchInstanceMetrics(context.Background(), cw, "mydb", now, 14)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if !stats.HasData {
		t.Error("expected HasData=true")
	}
	if stats.AvgCPU < 1.9 || stats.AvgCPU > 2.1 {
		t.Errorf("AvgCPU = %.1f, want ~2.0", stats.AvgCPU)
	}
	if stats.TotalConns != 0 {
		t.Errorf("TotalConns = %.0f, want 0", stats.TotalConns)
	}
}

func TestFetchInstanceMetricsActive(t *testing.T) {
	cw := newMockCWClient()
	cw.metrics["CPUUtilization"] = makeCPUDatapoints(50.0, 80.0, 14)
	cw.metrics["DatabaseConnections"] = makeConnDatapoints(500)

	stats, err := FetchInstanceMetrics(context.Background(), cw, "mydb", now, 14)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if stats.AvgCPU < 49 || stats.AvgCPU > 51 {
		t.Errorf("AvgCPU = %.1f, want ~50", stats.AvgCPU)
	}
	if stats.TotalConns != 500 {
		t.Errorf("TotalConns = %.0f, want 500", stats.TotalConns)
	}
}

func TestFetchInstanceMetricsNoData(t *testing.T) {
	cw := newMockCWClient()

	stats, err := FetchInstanceMetrics(context.Background(), cw, "mydb", now, 14)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if stats.HasData {
		t.Error("expected HasData=false with no datapoints")
	}
}

func TestFetchInstanceMetricsCPUError(t *testing.T) {
	cw := newMockCWClient()
	cw.err = errors.New("throttled")

	_, err := FetchInstanceMetrics(context.Background(), cw, "mydb", now, 14)
	if err == nil {
		t.Error("expected error")
	}
}

func TestFetchInstanceMetricsMaxCPU(t *testing.T) {
	cw := newMockCWClient()
	avg1, max1 := 10.0, 20.0
	avg2, max2 := 30.0, 90.0
	cw.metrics["CPUUtilization"] = &cloudwatch.GetMetricStatisticsOutput{
		Datapoints: []cwtypes.Datapoint{
			{Average: &avg1, Maximum: &max1},
			{Average: &avg2, Maximum: &max2},
		},
	}
	cw.metrics["DatabaseConnections"] = makeConnDatapoints(100)

	stats, err := FetchInstanceMetrics(context.Background(), cw, "mydb", now, 14)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if stats.MaxCPU != 90.0 {
		t.Errorf("MaxCPU = %.1f, want 90.0", stats.MaxCPU)
	}
	expectedAvg := (10.0 + 30.0) / 2
	if stats.AvgCPU < expectedAvg-0.1 || stats.AvgCPU > expectedAvg+0.1 {
		t.Errorf("AvgCPU = %.1f, want ~%.1f", stats.AvgCPU, expectedAvg)
	}
}

// WO-17@v2: a flat swap profile is parked-page noise and must report zero growth.
// This is the exact live-account shape (a write-heavy instance, 8.38MB flat over 14d)
// that WO-16 wrongly read as memory pressure.
func TestFetchInstanceMetricsFlatSwapIsNotGrowth(t *testing.T) {
	cw := newMockCWClient()
	cw.metrics["CPUUtilization"] = makeCPUDatapoints(8.0, 15.0, 14)
	cw.metrics["DatabaseConnections"] = makeConnDatapoints(50)
	cw.metrics["SwapUsage"] = makeFlatSwapSeries(8781824, 14)

	stats, err := FetchInstanceMetrics(context.Background(), cw, "mydb", now, 14)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if stats.SwapGrowthBytes != 0 {
		t.Errorf("SwapGrowthBytes = %.0f, want 0 for a flat swap profile", stats.SwapGrowthBytes)
	}
}

// WO-17@v2: reclaimed swap reports negative growth, never treated as pressure.
func TestFetchInstanceMetricsDecliningSwap(t *testing.T) {
	cw := newMockCWClient()
	cw.metrics["CPUUtilization"] = makeCPUDatapoints(8.0, 15.0, 14)
	cw.metrics["DatabaseConnections"] = makeConnDatapoints(50)
	cw.metrics["SwapUsage"] = makeSwapSeries(22851584, 21000000, 20594688)

	stats, err := FetchInstanceMetrics(context.Background(), cw, "mydb", now, 14)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if stats.SwapGrowthBytes >= 0 {
		t.Errorf("SwapGrowthBytes = %.0f, want negative for a declining swap profile", stats.SwapGrowthBytes)
	}
}

// WO-17@v2: genuinely growing swap reports the positive delta (live-account shape
// of a memory-pressured instance: 0.5MB -> 6.24MB).
func TestFetchInstanceMetricsGrowingSwap(t *testing.T) {
	cw := newMockCWClient()
	cw.metrics["CPUUtilization"] = makeCPUDatapoints(8.0, 15.0, 14)
	cw.metrics["DatabaseConnections"] = makeConnDatapoints(50)
	cw.metrics["SwapUsage"] = makeSwapSeries(524288, 2621440, 6545408)

	stats, err := FetchInstanceMetrics(context.Background(), cw, "mydb", now, 14)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	want := 6545408.0 - 524288.0
	if stats.SwapGrowthBytes != want {
		t.Errorf("SwapGrowthBytes = %.0f, want %.0f", stats.SwapGrowthBytes, want)
	}
}

// WO-17@v2: CloudWatch does not guarantee datapoint ordering, so growth must be
// computed after sorting by timestamp, not by slice position.
func TestFetchInstanceMetricsSwapGrowthUnordered(t *testing.T) {
	ordered := makeSwapSeries(524288, 2621440, 6545408)
	// Reverse the slice: chronologically identical, positionally backwards.
	dps := ordered.Datapoints
	for i, j := 0, len(dps)-1; i < j; i, j = i+1, j-1 {
		dps[i], dps[j] = dps[j], dps[i]
	}

	cw := newMockCWClient()
	cw.metrics["CPUUtilization"] = makeCPUDatapoints(8.0, 15.0, 14)
	cw.metrics["DatabaseConnections"] = makeConnDatapoints(50)
	cw.metrics["SwapUsage"] = ordered

	stats, err := FetchInstanceMetrics(context.Background(), cw, "mydb", now, 14)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	want := 6545408.0 - 524288.0
	if stats.SwapGrowthBytes != want {
		t.Errorf("SwapGrowthBytes = %.0f, want %.0f (datapoints must be sorted by timestamp)", stats.SwapGrowthBytes, want)
	}
}

// WO-17@v2: an absent SwapUsage metric reports zero growth, not pressure.
func TestFetchInstanceMetricsNoSwapMetric(t *testing.T) {
	cw := newMockCWClient()
	cw.metrics["CPUUtilization"] = makeCPUDatapoints(8.0, 15.0, 14)
	cw.metrics["DatabaseConnections"] = makeConnDatapoints(50)

	stats, err := FetchInstanceMetrics(context.Background(), cw, "mydb", now, 14)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if stats.SwapGrowthBytes != 0 {
		t.Errorf("SwapGrowthBytes = %.0f, want 0 when no SwapUsage metric is returned", stats.SwapGrowthBytes)
	}
}

// WO-17@v2: average write IOPS is surfaced for the I/O-bound countersignal.
func TestFetchInstanceMetricsWriteIOPS(t *testing.T) {
	cw := newMockCWClient()
	cw.metrics["CPUUtilization"] = makeCPUDatapoints(8.0, 15.0, 14)
	cw.metrics["DatabaseConnections"] = makeConnDatapoints(50)
	cw.metrics["WriteIOPS"] = makeWriteIOPSDatapoints(138.88, 14)

	stats, err := FetchInstanceMetrics(context.Background(), cw, "mydb", now, 14)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if stats.AvgWriteIOPS < 138.0 || stats.AvgWriteIOPS > 139.0 {
		t.Errorf("AvgWriteIOPS = %.2f, want ~138.88", stats.AvgWriteIOPS)
	}
}

// WO-18: average read IOPS is surfaced alongside write IOPS.
func TestFetchInstanceMetricsReadIOPS(t *testing.T) {
	cw := newMockCWClient()
	cw.metrics["CPUUtilization"] = makeCPUDatapoints(8.0, 15.0, 14)
	cw.metrics["DatabaseConnections"] = makeConnDatapoints(50)
	cw.metrics["WriteIOPS"] = makeWriteIOPSDatapoints(1.49, 14)
	cw.metrics["ReadIOPS"] = makeWriteIOPSDatapoints(0.33, 14)

	stats, err := FetchInstanceMetrics(context.Background(), cw, "mydb", now, 14)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if stats.AvgReadIOPS < 0.2 || stats.AvgReadIOPS > 0.4 {
		t.Errorf("AvgReadIOPS = %.2f, want ~0.33", stats.AvgReadIOPS)
	}
	if stats.AvgWriteIOPS < 1.3 || stats.AvgWriteIOPS > 1.6 {
		t.Errorf("AvgWriteIOPS = %.2f, want ~1.49", stats.AvgWriteIOPS)
	}
}
