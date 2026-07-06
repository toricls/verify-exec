package checks

import (
	"context"

	"github.com/toricls/verify-exec/internal/collect"
)

// IAM-006: with S3 session logging configured, the task role should
// hold the bucket-write permissions.
type iam006 struct{}

func NewIam006() Check { return &iam006{} }

func (c *iam006) ID() string   { return "IAM-006" }
func (c *iam006) Name() string { return "Task role can write S3 logs" }
func (c *iam006) DependsOn() []collect.Field {
	return []collect.Field{collect.FieldTaskRole, collect.FieldExecLogConfig}
}

func (c *iam006) Applicable(s *collect.Snapshot) bool {
	return resolved(s.ExecLogConfig).S3 != nil
}

func (c *iam006) Run(ctx context.Context, s *collect.Snapshot) []Finding {
	role := resolved(s.TaskRole)
	if f, done := roleUnavailableFinding(c.ID(), role); done {
		return []Finding{f}
	}
	return []Finding{simFinding(
		c.ID(), "role/"+role.Name, "role "+role.Name, role.S3Write, LevelWarn,
		"the S3 write actions for session logging",
		"Allow s3:PutObject and s3:GetBucketLocation (plus s3:GetEncryptionConfiguration for encrypted buckets) on the exec log bucket for the task role. "+docExec+"#ecs-exec-logging",
	)}
}
