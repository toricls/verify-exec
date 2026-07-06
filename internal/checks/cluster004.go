package checks

import (
	"context"
	"fmt"

	"github.com/toricls/verify-exec/internal/collect"
)

// CLUSTER-004: the CloudWatch Logs group for exec session logging
// exists; when cloudWatchEncryptionEnabled, the group must be
// KMS-encrypted.
type cluster004 struct{}

func NewCluster004() Check { return &cluster004{} }

func (c *cluster004) ID() string   { return "CLUSTER-004" }
func (c *cluster004) Name() string { return "Exec CloudWatch log group usable" }
func (c *cluster004) DependsOn() []collect.Field {
	return []collect.Field{collect.FieldExecLogConfig}
}

func (c *cluster004) Applicable(s *collect.Snapshot) bool {
	return resolved(s.ExecLogConfig).CloudWatch != nil
}

func (c *cluster004) Run(ctx context.Context, s *collect.Snapshot) []Finding {
	cfg := resolved(s.ExecLogConfig)
	cw := cfg.CloudWatch
	resource := "cluster/" + cfg.ClusterName

	switch {
	case cw.Err != nil:
		return []Finding{{
			CheckID:  c.ID(),
			Level:    LevelUnknown,
			Resource: resource,
			Message:  fmt.Sprintf("could not describe log group %q: %v", cw.GroupName, cw.Err),
		}}
	case cw.Group == nil:
		return []Finding{{
			CheckID:     c.ID(),
			Level:       LevelError,
			Resource:    resource,
			Message:     fmt.Sprintf("CloudWatch Logs group %q configured for exec logging does not exist", cw.GroupName),
			Remediation: "Create the log group, or fix cloudWatchLogGroupName in executeCommandConfiguration.",
		}}
	case cw.EncryptionEnabled && cw.Group.KmsKeyId == nil:
		return []Finding{{
			CheckID:     c.ID(),
			Level:       LevelError,
			Resource:    resource,
			Message:     fmt.Sprintf("cloudWatchEncryptionEnabled is true but log group %q is not KMS-encrypted", cw.GroupName),
			Remediation: "Associate a KMS key with the log group, or disable cloudWatchEncryptionEnabled.",
		}}
	default:
		return []Finding{{
			CheckID:  c.ID(),
			Level:    LevelOK,
			Resource: resource,
			Message:  fmt.Sprintf("log group %q exists and satisfies the encryption setting", cw.GroupName),
		}}
	}
}
