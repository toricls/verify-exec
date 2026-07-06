package collect

import (
	"context"
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	ecstypes "github.com/aws/aws-sdk-go-v2/service/ecs/types"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/smithy-go"
)

func collectCluster(ctx context.Context, deps Deps, s *Snapshot, cluster string) {
	out, err := deps.ECS.DescribeClusters(ctx, &ecs.DescribeClustersInput{
		Clusters: []string{cluster},
		Include:  []ecstypes.ClusterField{ecstypes.ClusterFieldConfigurations},
	})
	if err != nil {
		s.Cluster.Complete(nil, fmt.Errorf("DescribeClusters failed: %w", err))
		return
	}
	info := &ClusterInfo{Name: cluster}
	if len(out.Clusters) > 0 {
		info.Cluster = &out.Clusters[0]
		if name := aws.ToString(info.Cluster.ClusterName); name != "" {
			info.Name = name
		}
	}
	// No cluster and a MISSING failure both mean "confirmed absent":
	// resolve with Cluster == nil so CLUSTER-001 reports it as error
	// rather than a tool failure.
	s.Cluster.Complete(info, nil)
}

func collectExecLogConfig(ctx context.Context, deps Deps, s *Snapshot) {
	ci, err := s.Cluster.Get(ctx)
	if err != nil {
		s.ExecLogConfig.Complete(nil, fmt.Errorf("exec log config unavailable: %w", err))
		return
	}
	info := &LogConfigInfo{ClusterName: ci.Name}
	if ci.Cluster == nil || ci.Cluster.Configuration == nil || ci.Cluster.Configuration.ExecuteCommandConfiguration == nil {
		s.ExecLogConfig.Complete(info, nil)
		return
	}
	ecc := ci.Cluster.Configuration.ExecuteCommandConfiguration
	info.Logging = ecc.Logging

	if keyID := aws.ToString(ecc.KmsKeyId); keyID != "" {
		info.KMSKeyID = keyID
		out, err := deps.KMS.DescribeKey(ctx, &kms.DescribeKeyInput{KeyId: aws.String(keyID)})
		switch {
		case err == nil:
			info.KMSKey = out.KeyMetadata
		case apiErrorCode(err) == "NotFoundException":
			info.KMSKeyMissing = true
		default:
			info.KMSKeyErr = err
		}
	}

	if ecc.Logging == ecstypes.ExecuteCommandLoggingOverride && ecc.LogConfiguration != nil {
		lc := ecc.LogConfiguration
		if group := aws.ToString(lc.CloudWatchLogGroupName); group != "" {
			info.CloudWatch = lookupLogGroup(ctx, deps, group, lc.CloudWatchEncryptionEnabled)
		}
		if bucket := aws.ToString(lc.S3BucketName); bucket != "" {
			info.S3 = lookupS3Bucket(ctx, deps, bucket, aws.ToString(lc.S3KeyPrefix), lc.S3EncryptionEnabled)
		}
	}
	s.ExecLogConfig.Complete(info, nil)
}

func lookupLogGroup(ctx context.Context, deps Deps, group string, encryptionEnabled bool) *CloudWatchLogDest {
	dest := &CloudWatchLogDest{GroupName: group, EncryptionEnabled: encryptionEnabled}
	out, err := deps.Logs.DescribeLogGroups(ctx, &cloudwatchlogs.DescribeLogGroupsInput{
		LogGroupNamePrefix: aws.String(group),
	})
	if err != nil {
		dest.Err = err
		return dest
	}
	for i := range out.LogGroups {
		if aws.ToString(out.LogGroups[i].LogGroupName) == group {
			dest.Group = &out.LogGroups[i]
			break
		}
	}
	return dest
}

func lookupS3Bucket(ctx context.Context, deps Deps, bucket, prefix string, encryptionEnabled bool) *S3LogDest {
	dest := &S3LogDest{Bucket: bucket, KeyPrefix: prefix, EncryptionEnabled: encryptionEnabled}
	_, err := deps.S3.HeadBucket(ctx, &s3.HeadBucketInput{Bucket: aws.String(bucket)})
	switch code := apiErrorCode(err); {
	case err == nil:
		dest.Exists = true
	case code == "NotFound" || code == "NoSuchBucket":
		return dest // confirmed absent
	default:
		// e.g. 403: the bucket may exist but we cannot tell.
		dest.Err = err
		return dest
	}
	if encryptionEnabled {
		out, err := deps.S3.GetBucketEncryption(ctx, &s3.GetBucketEncryptionInput{Bucket: aws.String(bucket)})
		switch {
		case err == nil:
			dest.Encrypted = out.ServerSideEncryptionConfiguration != nil
		case apiErrorCode(err) == "ServerSideEncryptionConfigurationNotFoundError":
			// no encryption configured
		default:
			dest.EncryptionErr = err
		}
	}
	return dest
}

// apiErrorCode extracts the AWS API error code, or "" for nil / non-API
// errors.
func apiErrorCode(err error) string {
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		return apiErr.ErrorCode()
	}
	return ""
}
