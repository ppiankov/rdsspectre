package rds

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	awsrds "github.com/aws/aws-sdk-go-v2/service/rds"
)

// RDSAPI wraps the RDS SDK methods used by the scanner.
type RDSAPI interface {
	DescribeDBInstances(ctx context.Context, input *awsrds.DescribeDBInstancesInput, opts ...func(*awsrds.Options)) (*awsrds.DescribeDBInstancesOutput, error)
	DescribeDBSnapshots(ctx context.Context, input *awsrds.DescribeDBSnapshotsInput, opts ...func(*awsrds.Options)) (*awsrds.DescribeDBSnapshotsOutput, error)
	ListTagsForResource(ctx context.Context, input *awsrds.ListTagsForResourceInput, opts ...func(*awsrds.Options)) (*awsrds.ListTagsForResourceOutput, error)
}

// CloudWatchAPI wraps the CloudWatch SDK methods used by the scanner.
type CloudWatchAPI interface {
	GetMetricStatistics(ctx context.Context, input *cloudwatch.GetMetricStatisticsInput, opts ...func(*cloudwatch.Options)) (*cloudwatch.GetMetricStatisticsOutput, error)
}

// Client wraps AWS SDK configuration.
type Client struct {
	cfg aws.Config
}

// NewClient initializes an AWS client with optional profile and region.
func NewClient(ctx context.Context, profile, region string) (*Client, error) {
	var opts []func(*awsconfig.LoadOptions) error
	if profile != "" {
		opts = append(opts, awsconfig.WithSharedConfigProfile(profile))
	}
	if region != "" {
		opts = append(opts, awsconfig.WithRegion(region))
	}
	cfg, err := awsconfig.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, err
	}
	return &Client{cfg: cfg}, nil
}

// Region returns the configured AWS region.
func (c *Client) Region() string {
	return c.cfg.Region
}

// NewRDSClient creates an RDS service client.
func (c *Client) NewRDSClient() RDSAPI {
	return awsrds.NewFromConfig(c.cfg)
}

// NewCloudWatchClient creates a CloudWatch service client.
func (c *Client) NewCloudWatchClient() CloudWatchAPI {
	return cloudwatch.NewFromConfig(c.cfg)
}

// ListInstances returns all RDS instances using pagination.
func ListInstances(ctx context.Context, client RDSAPI) ([]Instance, error) {
	var instances []Instance
	var marker *string

	for {
		out, err := client.DescribeDBInstances(ctx, &awsrds.DescribeDBInstancesInput{
			Marker: marker,
		})
		if err != nil {
			return nil, err
		}
		for _, db := range out.DBInstances {
			instances = append(instances, convertInstance(db))
		}
		if out.Marker == nil {
			break
		}
		marker = out.Marker
	}

	return instances, nil
}

// ListSnapshots returns all manual RDS snapshots using pagination.
func ListSnapshots(ctx context.Context, client RDSAPI) ([]Snapshot, error) {
	var snapshots []Snapshot
	var marker *string

	for {
		out, err := client.DescribeDBSnapshots(ctx, &awsrds.DescribeDBSnapshotsInput{
			SnapshotType: aws.String("manual"),
			Marker:       marker,
		})
		if err != nil {
			return nil, err
		}
		for _, snap := range out.DBSnapshots {
			snapshots = append(snapshots, convertSnapshot(snap))
		}
		if out.Marker == nil {
			break
		}
		marker = out.Marker
	}

	return snapshots, nil
}
