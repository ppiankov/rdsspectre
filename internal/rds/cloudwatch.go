package rds

import (
	"context"
	"sort"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	awsrds "github.com/aws/aws-sdk-go-v2/service/rds"
)

// MetricStats holds summarized CloudWatch metric data.
type MetricStats struct {
	AvgCPU         float64
	MaxCPU         float64
	TotalConns     float64
	HasData        bool
	DatapointCount int
	// WO-17: SwapGrowthBytes is the change in swap between the earliest and
	// latest datapoint in the window. Growth indicates memory pressure; a flat
	// or declining value is parked-page noise (Linux commonly parks a few MB
	// at boot and never touches it again), which WO-16 wrongly read as pressure.
	SwapGrowthBytes float64
	// WO-17: AvgWriteIOPS is average write IOPS over the window. Sustained
	// write I/O is a countersignal against downsizing even when CPU is low,
	// because burstable instance classes scale EBS bandwidth with size.
	AvgWriteIOPS float64
}

// WO-7: enables tag-based exclusion in rds/scanner.go.
// FetchTags retrieves resource tags for an RDS instance or snapshot ARN as a
// key-value map, for tag-based exclusion matching.
func FetchTags(ctx context.Context, client RDSAPI, arn string) (map[string]string, error) {
	out, err := client.ListTagsForResource(ctx, &awsrds.ListTagsForResourceInput{
		ResourceName: aws.String(arn),
	})
	if err != nil {
		return nil, err
	}
	tags := make(map[string]string, len(out.TagList))
	for _, t := range out.TagList {
		if t.Key == nil {
			continue
		}
		tags[*t.Key] = deref(t.Value)
	}
	return tags, nil
}

// FetchInstanceMetrics retrieves CPU and connection metrics for an RDS instance.
func FetchInstanceMetrics(ctx context.Context, cw CloudWatchAPI, instanceID string, now time.Time, days int) (*MetricStats, error) {
	start := now.AddDate(0, 0, -days)
	period := int32(86400) // 1 day

	// Fetch CPU utilization
	cpuOut, err := cw.GetMetricStatistics(ctx, &cloudwatch.GetMetricStatisticsInput{
		Namespace:  aws.String("AWS/RDS"),
		MetricName: aws.String("CPUUtilization"),
		Dimensions: []cwtypes.Dimension{
			{Name: aws.String("DBInstanceIdentifier"), Value: aws.String(instanceID)},
		},
		StartTime:  aws.Time(start),
		EndTime:    aws.Time(now),
		Period:     aws.Int32(period),
		Statistics: []cwtypes.Statistic{cwtypes.StatisticAverage, cwtypes.StatisticMaximum},
	})
	if err != nil {
		return nil, err
	}

	// Fetch connection count
	connOut, err := cw.GetMetricStatistics(ctx, &cloudwatch.GetMetricStatisticsInput{
		Namespace:  aws.String("AWS/RDS"),
		MetricName: aws.String("DatabaseConnections"),
		Dimensions: []cwtypes.Dimension{
			{Name: aws.String("DBInstanceIdentifier"), Value: aws.String(instanceID)},
		},
		StartTime:  aws.Time(start),
		EndTime:    aws.Time(now),
		Period:     aws.Int32(period),
		Statistics: []cwtypes.Statistic{cwtypes.StatisticSum},
	})
	if err != nil {
		return nil, err
	}

	// WO-17: fetch swap usage to measure GROWTH across the window as a
	// memory-pressure countersignal for the oversized-instance check.
	swapOut, err := cw.GetMetricStatistics(ctx, &cloudwatch.GetMetricStatisticsInput{
		Namespace:  aws.String("AWS/RDS"),
		MetricName: aws.String("SwapUsage"),
		Dimensions: []cwtypes.Dimension{
			{Name: aws.String("DBInstanceIdentifier"), Value: aws.String(instanceID)},
		},
		StartTime:  aws.Time(start),
		EndTime:    aws.Time(now),
		Period:     aws.Int32(period),
		Statistics: []cwtypes.Statistic{cwtypes.StatisticMaximum},
	})
	if err != nil {
		return nil, err
	}

	// WO-17: fetch write IOPS as an I/O-bound countersignal; a low-CPU instance
	// sustaining heavy writes is not necessarily safe to downsize.
	writeOut, err := cw.GetMetricStatistics(ctx, &cloudwatch.GetMetricStatisticsInput{
		Namespace:  aws.String("AWS/RDS"),
		MetricName: aws.String("WriteIOPS"),
		Dimensions: []cwtypes.Dimension{
			{Name: aws.String("DBInstanceIdentifier"), Value: aws.String(instanceID)},
		},
		StartTime:  aws.Time(start),
		EndTime:    aws.Time(now),
		Period:     aws.Int32(period),
		Statistics: []cwtypes.Statistic{cwtypes.StatisticAverage},
	})
	if err != nil {
		return nil, err
	}

	stats := &MetricStats{}

	if len(cpuOut.Datapoints) > 0 {
		stats.HasData = true
		stats.DatapointCount = len(cpuOut.Datapoints)
		var totalAvg, maxVal float64
		for _, dp := range cpuOut.Datapoints {
			if dp.Average != nil {
				totalAvg += *dp.Average
			}
			if dp.Maximum != nil && *dp.Maximum > maxVal {
				maxVal = *dp.Maximum
			}
		}
		stats.AvgCPU = totalAvg / float64(len(cpuOut.Datapoints))
		stats.MaxCPU = maxVal
	}

	for _, dp := range connOut.Datapoints {
		if dp.Sum != nil {
			stats.TotalConns += *dp.Sum
		}
	}

	// WO-17: swap GROWTH, not presence. CloudWatch does not guarantee datapoint
	// ordering, so sort by timestamp before taking the first/last delta.
	stats.SwapGrowthBytes = swapGrowth(swapOut.Datapoints)

	// WO-17: average write IOPS across the window.
	var writeSum float64
	var writeCount int
	for _, dp := range writeOut.Datapoints {
		if dp.Average != nil {
			writeSum += *dp.Average
			writeCount++
		}
	}
	if writeCount > 0 {
		stats.AvgWriteIOPS = writeSum / float64(writeCount)
	}

	return stats, nil
}

// WO-17: swapGrowth returns the change in swap between the chronologically
// earliest and latest datapoint. Positive means swap grew (memory pressure);
// zero or negative means flat or reclaimed, which is parked-page noise.
func swapGrowth(datapoints []cwtypes.Datapoint) float64 {
	ordered := make([]cwtypes.Datapoint, 0, len(datapoints))
	for _, dp := range datapoints {
		if dp.Maximum != nil && dp.Timestamp != nil {
			ordered = append(ordered, dp)
		}
	}
	if len(ordered) < 2 {
		return 0
	}
	sort.Slice(ordered, func(i, j int) bool {
		return ordered[i].Timestamp.Before(*ordered[j].Timestamp)
	})
	return *ordered[len(ordered)-1].Maximum - *ordered[0].Maximum
}
