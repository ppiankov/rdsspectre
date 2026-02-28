package rds

import (
	"context"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	awsrds "github.com/aws/aws-sdk-go-v2/service/rds"
	rdstypes "github.com/aws/aws-sdk-go-v2/service/rds/types"
)

type mockRDSClient struct {
	instances   []rdstypes.DBInstance
	snapshots   []rdstypes.DBSnapshot
	descInstErr error
	descSnapErr error
	tagsForARN  map[string][]rdstypes.Tag
	listTagsErr error
	instPages   int // number of pages for instances (0 = single page)
	snapPages   int // number of pages for snapshots (0 = single page)
	instCallNum int
	snapCallNum int
}

func newMockRDSClient() *mockRDSClient {
	return &mockRDSClient{
		tagsForARN: make(map[string][]rdstypes.Tag),
	}
}

func (m *mockRDSClient) DescribeDBInstances(_ context.Context, input *awsrds.DescribeDBInstancesInput, _ ...func(*awsrds.Options)) (*awsrds.DescribeDBInstancesOutput, error) {
	if m.descInstErr != nil {
		return nil, m.descInstErr
	}
	m.instCallNum++
	if m.instPages > 0 && m.instCallNum < m.instPages {
		// Return a subset with a marker
		next := "next-page"
		return &awsrds.DescribeDBInstancesOutput{
			DBInstances: m.instances[:1],
			Marker:      &next,
		}, nil
	}
	// Return remaining instances (or all if single page)
	if m.instPages > 0 {
		return &awsrds.DescribeDBInstancesOutput{
			DBInstances: m.instances[1:],
		}, nil
	}
	return &awsrds.DescribeDBInstancesOutput{
		DBInstances: m.instances,
	}, nil
}

func (m *mockRDSClient) DescribeDBSnapshots(_ context.Context, _ *awsrds.DescribeDBSnapshotsInput, _ ...func(*awsrds.Options)) (*awsrds.DescribeDBSnapshotsOutput, error) {
	if m.descSnapErr != nil {
		return nil, m.descSnapErr
	}
	m.snapCallNum++
	if m.snapPages > 0 && m.snapCallNum < m.snapPages {
		next := "next-snap-page"
		return &awsrds.DescribeDBSnapshotsOutput{
			DBSnapshots: m.snapshots[:1],
			Marker:      &next,
		}, nil
	}
	if m.snapPages > 0 {
		return &awsrds.DescribeDBSnapshotsOutput{
			DBSnapshots: m.snapshots[1:],
		}, nil
	}
	return &awsrds.DescribeDBSnapshotsOutput{
		DBSnapshots: m.snapshots,
	}, nil
}

func (m *mockRDSClient) ListTagsForResource(_ context.Context, input *awsrds.ListTagsForResourceInput, _ ...func(*awsrds.Options)) (*awsrds.ListTagsForResourceOutput, error) {
	if m.listTagsErr != nil {
		return nil, m.listTagsErr
	}
	arn := ""
	if input.ResourceName != nil {
		arn = *input.ResourceName
	}
	return &awsrds.ListTagsForResourceOutput{
		TagList: m.tagsForARN[arn],
	}, nil
}

type mockCWClient struct {
	metrics map[string]*cloudwatch.GetMetricStatisticsOutput
	err     error
}

func newMockCWClient() *mockCWClient {
	return &mockCWClient{
		metrics: make(map[string]*cloudwatch.GetMetricStatisticsOutput),
	}
}

func (m *mockCWClient) GetMetricStatistics(_ context.Context, input *cloudwatch.GetMetricStatisticsInput, _ ...func(*cloudwatch.Options)) (*cloudwatch.GetMetricStatisticsOutput, error) {
	if m.err != nil {
		return nil, m.err
	}
	key := *input.MetricName
	if out, ok := m.metrics[key]; ok {
		return out, nil
	}
	return &cloudwatch.GetMetricStatisticsOutput{}, nil
}

func makeInstance(id, class, engine, version string, opts ...func(*rdstypes.DBInstance)) rdstypes.DBInstance {
	inst := rdstypes.DBInstance{
		DBInstanceIdentifier:  aws.String(id),
		DBInstanceClass:       aws.String(class),
		Engine:                aws.String(engine),
		EngineVersion:         aws.String(version),
		DBInstanceStatus:      aws.String("available"),
		StorageEncrypted:      aws.Bool(true),
		PubliclyAccessible:    aws.Bool(false),
		MultiAZ:               aws.Bool(true),
		DeletionProtection:    aws.Bool(true),
		BackupRetentionPeriod: aws.Int32(7),
		AllocatedStorage:      aws.Int32(100),
		StorageType:           aws.String("gp3"),
		DBParameterGroups: []rdstypes.DBParameterGroupStatus{
			{DBParameterGroupName: aws.String("default.postgres17"), ParameterApplyStatus: aws.String("in-sync")},
		},
	}
	for _, fn := range opts {
		fn(&inst)
	}
	return inst
}

func makeSnapshot(id, instanceID, engine string, createTime time.Time, storageGB int32) rdstypes.DBSnapshot {
	return rdstypes.DBSnapshot{
		DBSnapshotIdentifier: aws.String(id),
		DBInstanceIdentifier: aws.String(instanceID),
		Engine:               aws.String(engine),
		EngineVersion:        aws.String("17.2"),
		AllocatedStorage:     aws.Int32(storageGB),
		SnapshotCreateTime:   aws.Time(createTime),
		Status:               aws.String("available"),
	}
}

func makeCPUDatapoints(avgCPU, maxCPU float64, count int) *cloudwatch.GetMetricStatisticsOutput {
	dps := make([]cwtypes.Datapoint, count)
	for i := range dps {
		avg := avgCPU
		mx := maxCPU
		dps[i] = cwtypes.Datapoint{Average: &avg, Maximum: &mx}
	}
	return &cloudwatch.GetMetricStatisticsOutput{Datapoints: dps}
}

func makeConnDatapoints(totalConns float64) *cloudwatch.GetMetricStatisticsOutput {
	return &cloudwatch.GetMetricStatisticsOutput{
		Datapoints: []cwtypes.Datapoint{
			{Sum: &totalConns},
		},
	}
}
