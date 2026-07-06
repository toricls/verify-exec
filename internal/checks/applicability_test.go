package checks

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	ecstypes "github.com/aws/aws-sdk-go-v2/service/ecs/types"

	"github.com/toricls/verify-exec/internal/collect"
)

// Acceptance criterion for the full catalog: applicability-driven
// skips must be correct per launch type, KMS presence, log
// destinations, network mode, etc.
func TestApplicability(t *testing.T) {
	fargateTask := func(s *collect.Snapshot) {
		s.Task.Complete(&ecstypes.Task{
			TaskArn:    aws.String(taskArn),
			LaunchType: ecstypes.LaunchTypeFargate,
		}, nil)
	}
	ec2Task := func(s *collect.Snapshot) {
		s.Task.Complete(&ecstypes.Task{
			TaskArn:    aws.String(taskArn),
			LaunchType: ecstypes.LaunchTypeEc2,
		}, nil)
	}

	tests := []struct {
		name  string
		check Check
		setup func(s *collect.Snapshot)
		want  bool
	}{
		{"TASK-004 on Fargate", NewTask004(), fargateTask, true},
		{"TASK-004 on EC2", NewTask004(), ec2Task, false},
		{"TASK-005 on Fargate", NewTask005(), fargateTask, false},
		{"TASK-005 on EC2", NewTask005(), ec2Task, true},

		{"CLUSTER-002 without cluster", NewCluster002(), func(s *collect.Snapshot) {
			s.Cluster.Complete(&collect.ClusterInfo{Name: "c"}, nil)
		}, false},
		{"CLUSTER-002 with cluster", NewCluster002(), func(s *collect.Snapshot) {
			s.Cluster.Complete(&collect.ClusterInfo{Name: "c", Cluster: &ecstypes.Cluster{}}, nil)
		}, true},

		{"CLUSTER-003 without KMS", NewCluster003(), func(s *collect.Snapshot) {
			s.ExecLogConfig.Complete(&collect.LogConfigInfo{}, nil)
		}, false},
		{"CLUSTER-003 with KMS", NewCluster003(), func(s *collect.Snapshot) {
			s.ExecLogConfig.Complete(&collect.LogConfigInfo{KMSKeyID: "key-1"}, nil)
		}, true},
		{"CLUSTER-004 without CW dest", NewCluster004(), func(s *collect.Snapshot) {
			s.ExecLogConfig.Complete(&collect.LogConfigInfo{}, nil)
		}, false},
		{"CLUSTER-004 with CW dest", NewCluster004(), func(s *collect.Snapshot) {
			s.ExecLogConfig.Complete(&collect.LogConfigInfo{CloudWatch: &collect.CloudWatchLogDest{GroupName: "g"}}, nil)
		}, true},
		{"CLUSTER-005 without S3 dest", NewCluster005(), func(s *collect.Snapshot) {
			s.ExecLogConfig.Complete(&collect.LogConfigInfo{}, nil)
		}, false},
		{"CLUSTER-005 with S3 dest", NewCluster005(), func(s *collect.Snapshot) {
			s.ExecLogConfig.Complete(&collect.LogConfigInfo{S3: &collect.S3LogDest{Bucket: "b"}}, nil)
		}, true},

		{"TDEF-002 on Linux", NewTdef002(), func(s *collect.Snapshot) {
			s.TaskDefinition.Complete(&ecstypes.TaskDefinition{}, nil)
		}, true},
		{"TDEF-002 on Windows", NewTdef002(), func(s *collect.Snapshot) {
			s.TaskDefinition.Complete(&ecstypes.TaskDefinition{
				RuntimePlatform: &ecstypes.RuntimePlatform{
					OperatingSystemFamily: ecstypes.OSFamilyWindowsServer2019Core,
				},
			}, nil)
		}, false},

		{"TDEF-006 without proxy env", NewTdef006(), func(s *collect.Snapshot) {
			s.TaskDefinition.Complete(&ecstypes.TaskDefinition{
				ContainerDefinitions: []ecstypes.ContainerDefinition{{Name: aws.String("app")}},
			}, nil)
		}, false},
		{"TDEF-006 with proxy env", NewTdef006(), func(s *collect.Snapshot) {
			s.TaskDefinition.Complete(&ecstypes.TaskDefinition{
				ContainerDefinitions: []ecstypes.ContainerDefinition{{
					Name: aws.String("app"),
					Environment: []ecstypes.KeyValuePair{
						{Name: aws.String("HTTPS_PROXY"), Value: aws.String("http://proxy:3128")},
					},
				}},
			}, nil)
		}, true},

		{"IAM-003 without KMS", NewIam003(), func(s *collect.Snapshot) {
			s.ExecLogConfig.Complete(&collect.LogConfigInfo{}, nil)
		}, false},
		{"IAM-003 with KMS", NewIam003(), func(s *collect.Snapshot) {
			s.ExecLogConfig.Complete(&collect.LogConfigInfo{KMSKeyID: "key-1"}, nil)
		}, true},
		{"IAM-004 with KMS", NewIam004(), func(s *collect.Snapshot) {
			s.ExecLogConfig.Complete(&collect.LogConfigInfo{KMSKeyID: "key-1"}, nil)
		}, true},
		{"IAM-005 without CW dest", NewIam005(), func(s *collect.Snapshot) {
			s.ExecLogConfig.Complete(&collect.LogConfigInfo{}, nil)
		}, false},
		{"IAM-005 with CW dest", NewIam005(), func(s *collect.Snapshot) {
			s.ExecLogConfig.Complete(&collect.LogConfigInfo{CloudWatch: &collect.CloudWatchLogDest{GroupName: "g"}}, nil)
		}, true},
		{"IAM-006 with S3 dest", NewIam006(), func(s *collect.Snapshot) {
			s.ExecLogConfig.Complete(&collect.LogConfigInfo{S3: &collect.S3LogDest{Bucket: "b"}}, nil)
		}, true},

		{"NET-001 non-awsvpc", NewNet001(), func(s *collect.Snapshot) {
			s.Network.Complete(&collect.NetworkInfo{Awsvpc: false}, nil)
		}, false},
		{"NET-001 awsvpc", NewNet001(), func(s *collect.Snapshot) {
			s.Network.Complete(&collect.NetworkInfo{Awsvpc: true}, nil)
		}, true},
		{"NET-002 non-awsvpc", NewNet002(), func(s *collect.Snapshot) {
			s.Network.Complete(&collect.NetworkInfo{Awsvpc: false}, nil)
		}, false},

		{"NET-003 private subnet with KMS", NewNet003(), func(s *collect.Snapshot) {
			s.ExecLogConfig.Complete(&collect.LogConfigInfo{KMSKeyID: "key-1"}, nil)
			s.Network.Complete(&collect.NetworkInfo{Awsvpc: true, HasPublicRoute: aws.Bool(false)}, nil)
		}, true},
		{"NET-003 public subnet", NewNet003(), func(s *collect.Snapshot) {
			s.ExecLogConfig.Complete(&collect.LogConfigInfo{KMSKeyID: "key-1"}, nil)
			s.Network.Complete(&collect.NetworkInfo{Awsvpc: true, HasPublicRoute: aws.Bool(true)}, nil)
		}, false},
		{"NET-003 undetermined route", NewNet003(), func(s *collect.Snapshot) {
			s.ExecLogConfig.Complete(&collect.LogConfigInfo{KMSKeyID: "key-1"}, nil)
			s.Network.Complete(&collect.NetworkInfo{Awsvpc: true}, nil)
		}, false},
		{"NET-003 without KMS", NewNet003(), func(s *collect.Snapshot) {
			s.ExecLogConfig.Complete(&collect.LogConfigInfo{}, nil)
			s.Network.Complete(&collect.NetworkInfo{Awsvpc: true, HasPublicRoute: aws.Bool(false)}, nil)
		}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := collect.NewSnapshot()
			tt.setup(s)
			if got := tt.check.Applicable(s); got != tt.want {
				t.Errorf("%s.Applicable() = %v, want %v", tt.check.ID(), got, tt.want)
			}
		})
	}
}
