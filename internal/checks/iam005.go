package checks

import (
	"context"

	"github.com/toricls/verify-exec/internal/collect"
)

// IAM-005: with CloudWatch Logs session logging configured, the task
// role should hold the log-write permissions.
type iam005 struct{}

func NewIam005() Check { return &iam005{} }

func (c *iam005) ID() string   { return "IAM-005" }
func (c *iam005) Name() string { return "Task role can write CloudWatch logs" }
func (c *iam005) DependsOn() []collect.Field {
	return []collect.Field{collect.FieldTaskRole, collect.FieldExecLogConfig}
}

func (c *iam005) Applicable(s *collect.Snapshot) bool {
	return resolved(s.ExecLogConfig).CloudWatch != nil
}

func (c *iam005) Run(ctx context.Context, s *collect.Snapshot) []Finding {
	role := resolved(s.TaskRole)
	if f, done := roleUnavailableFinding(c.ID(), role); done {
		return []Finding{f}
	}
	return []Finding{simFinding(
		c.ID(), "role/"+role.Name, "role "+role.Name, role.CWLogs, LevelWarn,
		"the CloudWatch Logs write actions for session logging",
		"Allow logs:CreateLogStream, logs:DescribeLogStreams, logs:DescribeLogGroups and logs:PutLogEvents on the exec log group for the task role. "+docExec+"#ecs-exec-logging",
	)}
}
