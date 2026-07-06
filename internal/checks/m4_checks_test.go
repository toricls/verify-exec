package checks

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	logstypes "github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"
	ecstypes "github.com/aws/aws-sdk-go-v2/service/ecs/types"

	"github.com/toricls/verify-exec/internal/collect"
)

func taskFixture(status string) *ecstypes.Task {
	return &ecstypes.Task{TaskArn: aws.String(taskArn), LastStatus: aws.String(status)}
}

func runSingle(t *testing.T, c Check, s *collect.Snapshot) Finding {
	t.Helper()
	findings := c.Run(context.Background(), s)
	if len(findings) != 1 {
		t.Fatalf("%s: got %d findings, want 1: %+v", c.ID(), len(findings), findings)
	}
	return findings[0]
}

func TestCluster004LogGroupStates(t *testing.T) {
	run := func(cw *collect.CloudWatchLogDest) Finding {
		s := collect.NewSnapshot()
		s.ExecLogConfig.Complete(&collect.LogConfigInfo{ClusterName: "c", CloudWatch: cw}, nil)
		return runSingle(t, NewCluster004(), s)
	}

	if f := run(&collect.CloudWatchLogDest{GroupName: "g", Err: errors.New("AccessDenied")}); f.Level != LevelUnknown {
		t.Errorf("lookup failure: level = %s, want unknown", f.Level)
	}
	if f := run(&collect.CloudWatchLogDest{GroupName: "g"}); f.Level != LevelError {
		t.Errorf("missing group: level = %s, want error", f.Level)
	}
	if f := run(&collect.CloudWatchLogDest{
		GroupName: "g", EncryptionEnabled: true,
		Group: &logstypes.LogGroup{LogGroupName: aws.String("g")},
	}); f.Level != LevelError {
		t.Errorf("encryption required but group unencrypted: level = %s, want error", f.Level)
	}
	if f := run(&collect.CloudWatchLogDest{
		GroupName: "g", EncryptionEnabled: true,
		Group: &logstypes.LogGroup{LogGroupName: aws.String("g"), KmsKeyId: aws.String("key")},
	}); f.Level != LevelOK {
		t.Errorf("encrypted group: level = %s, want ok", f.Level)
	}
}

func TestCluster005BucketStates(t *testing.T) {
	run := func(dest *collect.S3LogDest) Finding {
		s := collect.NewSnapshot()
		s.ExecLogConfig.Complete(&collect.LogConfigInfo{ClusterName: "c", S3: dest}, nil)
		return runSingle(t, NewCluster005(), s)
	}

	if f := run(&collect.S3LogDest{Bucket: "b", Err: errors.New("Forbidden")}); f.Level != LevelUnknown {
		t.Errorf("HeadBucket failure: level = %s, want unknown", f.Level)
	}
	if f := run(&collect.S3LogDest{Bucket: "b", Exists: true, EncryptionEnabled: true, EncryptionErr: errors.New("AccessDenied")}); f.Level != LevelUnknown {
		t.Errorf("encryption lookup failure: level = %s, want unknown", f.Level)
	}
	if f := run(&collect.S3LogDest{Bucket: "b", Exists: true, EncryptionEnabled: true}); f.Level != LevelError {
		t.Errorf("unencrypted bucket: level = %s, want error", f.Level)
	}
	if f := run(&collect.S3LogDest{Bucket: "b", Exists: true, EncryptionEnabled: true, Encrypted: true}); f.Level != LevelOK {
		t.Errorf("encrypted bucket: level = %s, want ok", f.Level)
	}
}

func TestNet001SubnetLookupFailure(t *testing.T) {
	s := collect.NewSnapshot()
	s.Network.Complete(&collect.NetworkInfo{
		Awsvpc: true, SubnetID: "subnet-1", SubnetErr: errors.New("shared subnet"),
	}, nil)
	if f := runSingle(t, NewNet001(), s); f.Level != LevelUnknown {
		t.Errorf("level = %s, want unknown", f.Level)
	}
}

func TestNet003EndpointStates(t *testing.T) {
	run := func(network *collect.NetworkInfo) Finding {
		s := collect.NewSnapshot()
		s.Task.Complete(taskFixture("RUNNING"), nil)
		s.ExecLogConfig.Complete(&collect.LogConfigInfo{KMSKeyID: "key-1"}, nil)
		s.Network.Complete(network, nil)
		return runSingle(t, NewNet003(), s)
	}

	private := aws.Bool(false)
	if f := run(&collect.NetworkInfo{Awsvpc: true, VpcID: "vpc-1", HasPublicRoute: private,
		VPCEndpoints: []string{"com.amazonaws.ap-northeast-1.kms"}}); f.Level != LevelOK {
		t.Errorf("kms endpoint present: level = %s, want ok", f.Level)
	}
	if f := run(&collect.NetworkInfo{Awsvpc: true, VpcID: "vpc-1", HasPublicRoute: private}); f.Level != LevelWarn {
		t.Errorf("kms endpoint absent: level = %s, want warn", f.Level)
	}
	if f := run(&collect.NetworkInfo{Awsvpc: true, VpcID: "vpc-1", HasPublicRoute: private,
		EndpointErr: errors.New("UnauthorizedOperation")}); f.Level != LevelUnknown {
		t.Errorf("endpoint lookup failure: level = %s, want unknown", f.Level)
	}
}

func TestTdef005UnresolvableRole(t *testing.T) {
	s := collect.NewSnapshot()
	s.Task.Complete(taskFixture("RUNNING"), nil)
	s.TaskRole.Complete(&collect.IAMRoleInfo{
		Source: collect.RoleSourceNone, ResolveErr: errors.New("DescribeInstances denied"),
	}, nil)
	if f := runSingle(t, NewTdef005(), s); f.Level != LevelUnknown {
		t.Errorf("level = %s, want unknown", f.Level)
	}
}

func TestIamRoleCheckUnknownOnResolveError(t *testing.T) {
	s := collect.NewSnapshot()
	s.TaskRole.Complete(&collect.IAMRoleInfo{
		Source: collect.RoleSourceNone, ResolveErr: errors.New("DescribeInstances denied"),
	}, nil)
	if f := runSingle(t, NewIam001(), s); f.Level != LevelUnknown {
		t.Errorf("level = %s, want unknown", f.Level)
	}
}
