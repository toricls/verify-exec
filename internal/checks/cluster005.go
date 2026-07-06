package checks

import (
	"context"
	"fmt"

	"github.com/toricls/verify-exec/internal/collect"
)

// CLUSTER-005: the S3 bucket for exec session logging exists; when
// s3EncryptionEnabled, bucket encryption must be configured.
type cluster005 struct{}

func NewCluster005() Check { return &cluster005{} }

func (c *cluster005) ID() string   { return "CLUSTER-005" }
func (c *cluster005) Name() string { return "Exec S3 bucket usable" }
func (c *cluster005) DependsOn() []collect.Field {
	return []collect.Field{collect.FieldExecLogConfig}
}

func (c *cluster005) Applicable(s *collect.Snapshot) bool {
	return resolved(s.ExecLogConfig).S3 != nil
}

func (c *cluster005) Run(ctx context.Context, s *collect.Snapshot) []Finding {
	cfg := resolved(s.ExecLogConfig)
	dest := cfg.S3
	resource := "cluster/" + cfg.ClusterName

	switch {
	case dest.Err != nil:
		return []Finding{{
			CheckID:  c.ID(),
			Level:    LevelUnknown,
			Resource: resource,
			Message:  fmt.Sprintf("could not verify S3 bucket %q: %v", dest.Bucket, dest.Err),
		}}
	case !dest.Exists:
		return []Finding{{
			CheckID:     c.ID(),
			Level:       LevelError,
			Resource:    resource,
			Message:     fmt.Sprintf("S3 bucket %q configured for exec logging does not exist", dest.Bucket),
			Remediation: "Create the bucket, or fix s3BucketName in executeCommandConfiguration.",
		}}
	case dest.EncryptionEnabled && dest.EncryptionErr != nil:
		return []Finding{{
			CheckID:  c.ID(),
			Level:    LevelUnknown,
			Resource: resource,
			Message:  fmt.Sprintf("could not verify encryption of S3 bucket %q: %v", dest.Bucket, dest.EncryptionErr),
		}}
	case dest.EncryptionEnabled && !dest.Encrypted:
		return []Finding{{
			CheckID:     c.ID(),
			Level:       LevelError,
			Resource:    resource,
			Message:     fmt.Sprintf("s3EncryptionEnabled is true but bucket %q has no encryption configuration", dest.Bucket),
			Remediation: "Configure default encryption on the bucket, or disable s3EncryptionEnabled.",
		}}
	default:
		return []Finding{{
			CheckID:  c.ID(),
			Level:    LevelOK,
			Resource: resource,
			Message:  fmt.Sprintf("S3 bucket %q exists and satisfies the encryption setting", dest.Bucket),
		}}
	}
}
