package cloudsql

import (
	"context"
	"fmt"
	"time"

	sqladmin "google.golang.org/api/sqladmin/v1beta4"
)

// CloudSQLAPI abstracts the Cloud SQL Admin API for testability.
type CloudSQLAPI interface {
	ListInstances(ctx context.Context, project string) ([]Instance, error)
}

// Instance is a domain type for a Cloud SQL instance.
type Instance struct {
	Name               string
	Project            string
	DatabaseVersion    string // e.g., "MYSQL_8_0", "POSTGRES_15"
	State              string // "RUNNABLE", "SUSPENDED", etc.
	Tier               string // machine type, e.g., "db-f1-micro"
	Region             string
	AvailabilityType   string // "ZONAL" or "REGIONAL"
	DataDiskSizeGB     int64
	DataDiskType       string // "PD_SSD", "PD_HDD"
	BackupEnabled      bool
	DeletionProtection bool
	IPv4Enabled        bool
	AuthorizedNetworks []string // CIDR values from ipConfiguration
	IsReplica          bool
	MasterInstanceName string
	CreateTime         time.Time
	SelfLink           string
}

// Client wraps a Cloud SQL Admin API service.
type Client struct {
	svc     *sqladmin.Service
	project string
}

// NewClient creates a Cloud SQL client with default credentials.
func NewClient(ctx context.Context, project string) (*Client, error) {
	svc, err := sqladmin.NewService(ctx)
	if err != nil {
		return nil, fmt.Errorf("create Cloud SQL service: %w", err)
	}
	return &Client{svc: svc, project: project}, nil
}

// Project returns the configured project ID.
func (c *Client) Project() string {
	return c.project
}

// ListInstances fetches all Cloud SQL instances in the project.
func (c *Client) ListInstances(ctx context.Context, project string) ([]Instance, error) {
	var instances []Instance

	req := c.svc.Instances.List(project).Context(ctx)
	err := req.Pages(ctx, func(resp *sqladmin.InstancesListResponse) error {
		for _, db := range resp.Items {
			instances = append(instances, convertInstance(db))
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("list Cloud SQL instances: %w", err)
	}

	return instances, nil
}

// convertInstance maps a Cloud SQL API instance to the domain type.
func convertInstance(db *sqladmin.DatabaseInstance) Instance {
	inst := Instance{
		Name:               db.Name,
		Project:            db.Project,
		DatabaseVersion:    db.DatabaseVersion,
		State:              db.State,
		Region:             db.Region,
		SelfLink:           db.SelfLink,
		IsReplica:          db.InstanceType == "READ_REPLICA_INSTANCE",
		MasterInstanceName: db.MasterInstanceName,
	}

	if db.Settings != nil {
		inst.Tier = db.Settings.Tier
		inst.AvailabilityType = db.Settings.AvailabilityType
		inst.DataDiskSizeGB = db.Settings.DataDiskSizeGb
		inst.DataDiskType = db.Settings.DataDiskType
		inst.DeletionProtection = db.Settings.DeletionProtectionEnabled

		if db.Settings.BackupConfiguration != nil {
			inst.BackupEnabled = db.Settings.BackupConfiguration.Enabled
		}

		if db.Settings.IpConfiguration != nil {
			inst.IPv4Enabled = db.Settings.IpConfiguration.Ipv4Enabled
			for _, net := range db.Settings.IpConfiguration.AuthorizedNetworks {
				inst.AuthorizedNetworks = append(inst.AuthorizedNetworks, net.Value)
			}
		}
	}

	if db.CreateTime != "" {
		if t, err := time.Parse(time.RFC3339, db.CreateTime); err == nil {
			inst.CreateTime = t
		}
	}

	return inst
}
