package checks

import (
	"context"
	"fmt"

	ecstypes "github.com/aws/aws-sdk-go-v2/service/ecs/types"

	"github.com/toricls/verify-exec/internal/collect"
)

// CLUSTER-002: audit logging for execute command sessions is
// configured (logging != NONE).
type cluster002 struct{}

func NewCluster002() Check { return &cluster002{} }

func (c *cluster002) ID() string                          { return "CLUSTER-002" }
func (c *cluster002) Name() string                        { return "Exec audit logging configured" }
func (c *cluster002) DependsOn() []collect.Field          { return []collect.Field{collect.FieldCluster} }
func (c *cluster002) Applicable(s *collect.Snapshot) bool { return resolved(s.Cluster).Cluster != nil }

func (c *cluster002) Run(ctx context.Context, s *collect.Snapshot) []Finding {
	info := resolved(s.Cluster)
	resource := "cluster/" + info.Name
	const remediation = "Configure executeCommandConfiguration with logging DEFAULT or OVERRIDE on the cluster to keep an audit trail of exec sessions. " + docExec + "#ecs-exec-logging"

	cluster := info.Cluster
	if cluster.Configuration == nil || cluster.Configuration.ExecuteCommandConfiguration == nil {
		return []Finding{{
			CheckID:     c.ID(),
			Level:       LevelWarn,
			Resource:    resource,
			Message:     "no executeCommandConfiguration on the cluster; exec session audit logging is not configured",
			Remediation: remediation,
		}}
	}
	logging := cluster.Configuration.ExecuteCommandConfiguration.Logging
	if logging == ecstypes.ExecuteCommandLoggingNone {
		return []Finding{{
			CheckID:     c.ID(),
			Level:       LevelWarn,
			Resource:    resource,
			Message:     "executeCommandConfiguration logging is NONE; exec sessions are not audited",
			Remediation: remediation,
		}}
	}
	return []Finding{{
		CheckID:  c.ID(),
		Level:    LevelOK,
		Resource: resource,
		Message:  fmt.Sprintf("exec session logging is %s", logging),
	}}
}
