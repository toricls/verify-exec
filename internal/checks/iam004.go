package checks

import (
	"context"

	"github.com/toricls/verify-exec/internal/collect"
)

// IAM-004: with KMS session encryption configured, the task role must
// be allowed kms:Decrypt.
type iam004 struct{}

func NewIam004() Check { return &iam004{} }

func (c *iam004) ID() string   { return "IAM-004" }
func (c *iam004) Name() string { return "Task role can decrypt with KMS key" }
func (c *iam004) DependsOn() []collect.Field {
	return []collect.Field{collect.FieldTaskRole, collect.FieldExecLogConfig}
}

func (c *iam004) Applicable(s *collect.Snapshot) bool {
	return resolved(s.ExecLogConfig).KMSKeyID != ""
}

func (c *iam004) Run(ctx context.Context, s *collect.Snapshot) []Finding {
	role := resolved(s.TaskRole)
	if f, done := roleUnavailableFinding(c.ID(), role); done {
		return []Finding{f}
	}
	return []Finding{simFinding(
		c.ID(), "role/"+role.Name, "role "+role.Name, role.KMSDecrypt, LevelError,
		"kms:Decrypt on the exec session key",
		"Allow kms:Decrypt on the configured KMS key for the task role. "+docExec+"#ecs-exec-considerations",
	)}
}
