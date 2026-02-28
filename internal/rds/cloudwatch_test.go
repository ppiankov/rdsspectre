package rds

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
)

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
