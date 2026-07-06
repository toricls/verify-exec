package collect

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	logstypes "github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	ecstypes "github.com/aws/aws-sdk-go-v2/service/ecs/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"

	"github.com/toricls/verify-exec/internal/awsapi/awsapitest"
)

func withOverrideLogging(f *awsapitest.Fakes) {
	f.ECS.DescribeClustersFn = func(*ecs.DescribeClustersInput) (*ecs.DescribeClustersOutput, error) {
		return &ecs.DescribeClustersOutput{Clusters: []ecstypes.Cluster{{
			ClusterName: aws.String("my-cluster"),
			Status:      aws.String("ACTIVE"),
			Configuration: &ecstypes.ClusterConfiguration{
				ExecuteCommandConfiguration: &ecstypes.ExecuteCommandConfiguration{
					Logging: ecstypes.ExecuteCommandLoggingOverride,
					LogConfiguration: &ecstypes.ExecuteCommandLogConfiguration{
						CloudWatchLogGroupName: aws.String("/ecs/exec"),
						S3BucketName:           aws.String("exec-logs"),
						S3EncryptionEnabled:    true,
					},
				},
			},
		}}}, nil
	}
}

func TestExecLogConfigMatchesLogGroupNameExactly(t *testing.T) {
	f := awsapitest.New()
	withTask(f, runningTask())
	withOverrideLogging(f)
	f.Logs.DescribeLogGroupsFn = func(in *cloudwatchlogs.DescribeLogGroupsInput) (*cloudwatchlogs.DescribeLogGroupsOutput, error) {
		// DescribeLogGroups is a prefix query: a longer-named group
		// must not satisfy the exact-name check.
		return &cloudwatchlogs.DescribeLogGroupsOutput{LogGroups: []logstypes.LogGroup{
			{LogGroupName: aws.String("/ecs/exec-other")},
		}}, nil
	}

	s := Collect(context.Background(), depsOf(f), "my-cluster", "abc123")
	logCfg, err := s.ExecLogConfig.Get(context.Background())
	if err != nil {
		t.Fatalf("ExecLogConfig.Get() error = %v", err)
	}
	if logCfg.CloudWatch == nil || logCfg.CloudWatch.Group != nil {
		t.Errorf("CloudWatch = %+v, want configured dest with no exact-name match", logCfg.CloudWatch)
	}
}

func TestExecLogConfigS3ForbiddenLeavesExistenceUnknown(t *testing.T) {
	f := awsapitest.New()
	withTask(f, runningTask())
	withOverrideLogging(f)
	f.S3.HeadBucketFn = func(*s3.HeadBucketInput) (*s3.HeadBucketOutput, error) {
		return nil, &smithy.GenericAPIError{Code: "Forbidden", Message: "403"}
	}

	s := Collect(context.Background(), depsOf(f), "my-cluster", "abc123")
	logCfg, err := s.ExecLogConfig.Get(context.Background())
	if err != nil {
		t.Fatalf("ExecLogConfig.Get() error = %v", err)
	}
	if logCfg.S3 == nil || logCfg.S3.Err == nil || logCfg.S3.Exists {
		t.Errorf("S3 = %+v, want embedded error with existence unknown", logCfg.S3)
	}
}

func TestApiErrorCode(t *testing.T) {
	if code := apiErrorCode(&smithy.GenericAPIError{Code: "NotFound"}); code != "NotFound" {
		t.Errorf("apiErrorCode = %q, want NotFound", code)
	}
	if code := apiErrorCode(errors.New("plain")); code != "" {
		t.Errorf("apiErrorCode(plain error) = %q, want empty", code)
	}
	if code := apiErrorCode(nil); code != "" {
		t.Errorf("apiErrorCode(nil) = %q, want empty", code)
	}
}

func TestCallerIdentityAssumedRoleConversion(t *testing.T) {
	f := awsapitest.New()
	withTask(f, runningTask())
	f.STS.GetCallerIdentityFn = func(*sts.GetCallerIdentityInput) (*sts.GetCallerIdentityOutput, error) {
		return &sts.GetCallerIdentityOutput{
			Account: aws.String("123456789012"),
			Arn:     aws.String("arn:aws:sts::123456789012:assumed-role/admin-role/session-1"),
		}, nil
	}

	s := Collect(context.Background(), depsOf(f), "my-cluster", "abc123")
	caller, err := s.CallerIdentity.Get(context.Background())
	if err != nil {
		t.Fatalf("CallerIdentity.Get() error = %v", err)
	}
	if caller.SimPrincipal != "arn:aws:iam::123456789012:role/admin-role" {
		t.Errorf("SimPrincipal = %q, want the underlying role ARN", caller.SimPrincipal)
	}
	if caller.ExecuteCommand == nil || !caller.ExecuteCommand.Allowed() {
		t.Errorf("ExecuteCommand = %+v, want allowed", caller.ExecuteCommand)
	}
}

func TestCallerIdentityRootBypassesSimulation(t *testing.T) {
	f := awsapitest.New()
	withTask(f, runningTask())
	f.STS.GetCallerIdentityFn = func(*sts.GetCallerIdentityInput) (*sts.GetCallerIdentityOutput, error) {
		return &sts.GetCallerIdentityOutput{
			Account: aws.String("123456789012"),
			Arn:     aws.String("arn:aws:iam::123456789012:root"),
		}, nil
	}
	f.IAM.SimulatePrincipalPolicyFn = func(*iam.SimulatePrincipalPolicyInput) (*iam.SimulatePrincipalPolicyOutput, error) {
		t.Error("SimulatePrincipalPolicy must not be called for the root user")
		return &iam.SimulatePrincipalPolicyOutput{}, nil
	}

	s := Collect(context.Background(), depsOf(f), "my-cluster", "abc123")
	caller, err := s.CallerIdentity.Get(context.Background())
	if err != nil {
		t.Fatalf("CallerIdentity.Get() error = %v", err)
	}
	if caller.ExecuteCommand == nil || !caller.ExecuteCommand.Allowed() || caller.ExecuteCommand.Note == "" {
		t.Errorf("ExecuteCommand = %+v, want allowed with a root note", caller.ExecuteCommand)
	}
}
