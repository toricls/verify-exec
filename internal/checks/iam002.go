package checks

import (
	"context"

	"github.com/toricls/verify-exec/internal/collect"
)

// IAM-002: the caller is allowed ecs:ExecuteCommand on the target task
// and cluster.
type iam002 struct{}

func NewIam002() Check { return &iam002{} }

func (c *iam002) ID() string   { return "IAM-002" }
func (c *iam002) Name() string { return "Caller can ExecuteCommand" }
func (c *iam002) DependsOn() []collect.Field {
	return []collect.Field{collect.FieldCallerIdentity, collect.FieldTask}
}
func (c *iam002) Applicable(s *collect.Snapshot) bool { return true }

func (c *iam002) Run(ctx context.Context, s *collect.Snapshot) []Finding {
	caller := resolved(s.CallerIdentity)
	return []Finding{simFinding(
		c.ID(), callerResource(caller), "caller "+arnTail(caller.Arn), caller.ExecuteCommand, LevelError,
		"ecs:ExecuteCommand on the target task/cluster",
		"Allow ecs:ExecuteCommand on the cluster and task ARNs for your IAM identity. "+docExec+"#ecs-exec-enabling-and-using",
	)}
}

func callerResource(caller *collect.CallerInfo) string {
	return "caller/" + arnTail(caller.Arn)
}
