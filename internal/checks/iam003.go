package checks

import (
	"context"

	"github.com/toricls/verify-exec/internal/collect"
)

// IAM-003: with KMS session encryption configured, the caller must be
// allowed kms:GenerateDataKey.
type iam003 struct{}

func NewIam003() Check { return &iam003{} }

func (c *iam003) ID() string   { return "IAM-003" }
func (c *iam003) Name() string { return "Caller can generate KMS data key" }
func (c *iam003) DependsOn() []collect.Field {
	return []collect.Field{collect.FieldCallerIdentity, collect.FieldExecLogConfig}
}

func (c *iam003) Applicable(s *collect.Snapshot) bool {
	return resolved(s.ExecLogConfig).KMSKeyID != ""
}

func (c *iam003) Run(ctx context.Context, s *collect.Snapshot) []Finding {
	caller := resolved(s.CallerIdentity)
	return []Finding{simFinding(
		c.ID(), callerResource(caller), "caller "+arnTail(caller.Arn), caller.KMSGenerateDataKey, LevelError,
		"kms:GenerateDataKey on the exec session key",
		"Allow kms:GenerateDataKey on the configured KMS key for your IAM identity. "+docExec+"#ecs-exec-considerations",
	)}
}
