package rds

import (
	"context"
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
}

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

	return stats, nil
}
