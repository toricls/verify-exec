package checks

import (
	"context"
	"fmt"

	"github.com/toricls/verify-exec/internal/collect"
)

// CLUSTER-003: the KMS key configured for exec session encryption
// exists and is enabled.
type cluster003 struct{}

func NewCluster003() Check { return &cluster003{} }

func (c *cluster003) ID() string   { return "CLUSTER-003" }
func (c *cluster003) Name() string { return "Exec KMS key usable" }
func (c *cluster003) DependsOn() []collect.Field {
	return []collect.Field{collect.FieldExecLogConfig}
}

func (c *cluster003) Applicable(s *collect.Snapshot) bool {
	return resolved(s.ExecLogConfig).KMSKeyID != ""
}

func (c *cluster003) Run(ctx context.Context, s *collect.Snapshot) []Finding {
	cfg := resolved(s.ExecLogConfig)
	resource := "cluster/" + cfg.ClusterName

	switch {
	case cfg.KMSKeyErr != nil:
		return []Finding{{
			CheckID:  c.ID(),
			Level:    LevelUnknown,
			Resource: resource,
			Message:  fmt.Sprintf("could not describe KMS key %q: %v", cfg.KMSKeyID, cfg.KMSKeyErr),
		}}
	case cfg.KMSKeyMissing:
		return []Finding{{
			CheckID:     c.ID(),
			Level:       LevelError,
			Resource:    resource,
			Message:     fmt.Sprintf("KMS key %q configured on the cluster does not exist", cfg.KMSKeyID),
			Remediation: "Point executeCommandConfiguration.kmsKeyId at an existing key, or remove it.",
		}}
	case cfg.KMSKey == nil:
		return []Finding{{
			CheckID:  c.ID(),
			Level:    LevelUnknown,
			Resource: resource,
			Message:  fmt.Sprintf("no key metadata available for %q", cfg.KMSKeyID),
		}}
	case !cfg.KMSKey.Enabled:
		return []Finding{{
			CheckID:     c.ID(),
			Level:       LevelError,
			Resource:    resource,
			Message:     fmt.Sprintf("KMS key %q is disabled (state: %s)", cfg.KMSKeyID, cfg.KMSKey.KeyState),
			Remediation: "Enable the KMS key or configure a different key.",
		}}
	default:
		return []Finding{{
			CheckID:  c.ID(),
			Level:    LevelOK,
			Resource: resource,
			Message:  fmt.Sprintf("KMS key %q exists and is enabled", cfg.KMSKeyID),
		}}
	}
}
