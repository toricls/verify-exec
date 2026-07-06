package checks

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"

	"github.com/toricls/verify-exec/internal/collect"
)

// CLUSTER-001: the cluster exists and is ACTIVE.
type cluster001 struct{}

func NewCluster001() Check { return &cluster001{} }

func (c *cluster001) ID() string                          { return "CLUSTER-001" }
func (c *cluster001) Name() string                        { return "Cluster is active" }
func (c *cluster001) DependsOn() []collect.Field          { return []collect.Field{collect.FieldCluster} }
func (c *cluster001) Applicable(s *collect.Snapshot) bool { return true }

func (c *cluster001) Run(ctx context.Context, s *collect.Snapshot) []Finding {
	info := resolved(s.Cluster)
	resource := "cluster/" + info.Name

	if info.Cluster == nil {
		return []Finding{{
			CheckID:     c.ID(),
			Level:       LevelError,
			Resource:    resource,
			Message:     fmt.Sprintf("cluster %q does not exist", info.Name),
			Remediation: "Check the cluster name and the target region/account.",
		}}
	}
	if status := aws.ToString(info.Cluster.Status); status != "ACTIVE" {
		return []Finding{{
			CheckID:     c.ID(),
			Level:       LevelError,
			Resource:    resource,
			Message:     fmt.Sprintf("cluster status is %s (want ACTIVE)", status),
			Remediation: "ECS Exec requires an ACTIVE cluster.",
		}}
	}
	return []Finding{{
		CheckID:  c.ID(),
		Level:    LevelOK,
		Resource: resource,
		Message:  "cluster is ACTIVE",
	}}
}
