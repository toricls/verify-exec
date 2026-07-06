// Package scenario runs fixture-driven integration tests: each
// testdata/*.json file describes the AWS-side state of one situation
// (as raw API shapes plus a few environment knobs) and the worst
// finding level expected per check. The harness wires the fixture into
// awsapitest fakes, runs the real collectors and the full check
// registry through the runner, and compares the outcome.
//
// LOCAL-* checks are excluded: they probe the machine running the
// tests, not the fixture.
package scenario

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	logstypes "github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	ecstypes "github.com/aws/aws-sdk-go-v2/service/ecs/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"

	"github.com/toricls/verify-exec/internal/awsapi/awsapitest"
	"github.com/toricls/verify-exec/internal/checks"
	"github.com/toricls/verify-exec/internal/collect"
	"github.com/toricls/verify-exec/internal/report"
	"github.com/toricls/verify-exec/internal/runner"
)

type scenario struct {
	// Raw AWS API shapes (JSON field matching is case-insensitive, so
	// real describe-* output keys like "taskArn" bind directly).
	Task              *ecstypes.Task              `json:"task"`
	TaskDefinition    *ecstypes.TaskDefinition    `json:"taskDefinition"`
	Cluster           *ecstypes.Cluster           `json:"cluster"`
	ContainerInstance *ecstypes.ContainerInstance `json:"containerInstance"`

	Env environment `json:"env"`

	// Expect maps checkID → worst finding level for that check.
	// Checks not listed are not asserted.
	Expect map[string]string `json:"expect"`
}

type environment struct {
	CallerArn              string   `json:"callerArn"`
	KMSKeyMissing          bool     `json:"kmsKeyMissing"`
	KMSKeyDisabled         bool     `json:"kmsKeyDisabled"`
	LogGroupExists         bool     `json:"logGroupExists"`
	LogGroupKMSEncrypted   bool     `json:"logGroupKmsEncrypted"`
	S3BucketExists         bool     `json:"s3BucketExists"`
	S3BucketEncrypted      bool     `json:"s3BucketEncrypted"`
	Subnet                 *subnet  `json:"subnet"`
	PublicRoute            *bool    `json:"publicRoute"`
	VPCEndpoints           []string `json:"vpcEndpoints"`
	InstanceProfileRoleArn string   `json:"instanceProfileRoleArn"`
	DenyActions            []string `json:"denyActions"`
	ConditionDenyActions   []string `json:"conditionDenyActions"`
}

type subnet struct {
	SubnetID   string `json:"subnetId"`
	VpcID      string `json:"vpcId"`
	IPv6Native bool   `json:"ipv6Native"`
}

func TestScenarios(t *testing.T) {
	files, err := filepath.Glob("testdata/*.json")
	if err != nil || len(files) == 0 {
		t.Fatalf("no scenario fixtures found: %v", err)
	}
	for _, file := range files {
		t.Run(strings.TrimSuffix(filepath.Base(file), ".json"), func(t *testing.T) {
			runScenario(t, file)
		})
	}
}

func runScenario(t *testing.T, file string) {
	raw, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	var sc scenario
	if err := json.Unmarshal(raw, &sc); err != nil {
		t.Fatalf("invalid fixture: %v", err)
	}
	if sc.Task == nil || sc.TaskDefinition == nil {
		t.Fatal("fixture must define task and taskDefinition")
	}

	taskID := arnTail(aws.ToString(sc.Task.TaskArn))
	clusterName := arnTail(aws.ToString(sc.Task.ClusterArn))

	snapshot := collect.Collect(context.Background(), collect.Deps{
		ECS: fakeECS(&sc), STS: fakeSTS(&sc), IAM: fakeIAM(&sc),
		EC2: fakeEC2(&sc), KMS: fakeKMS(&sc), Logs: fakeLogs(&sc), S3: fakeS3(&sc),
	}, clusterName, taskID)

	var nonLocal []checks.Check
	for _, c := range checks.All() {
		if !strings.HasPrefix(c.ID(), "LOCAL-") {
			nonLocal = append(nonLocal, c)
		}
	}

	findings, runErr := runner.Run(context.Background(), runner.Options{
		Checks:   nonLocal,
		Snapshot: snapshot,
		Renderer: report.NewPlainRenderer(io.Discard),
		TaskID:   taskID,
	})
	if runErr != nil {
		t.Fatalf("runner.Run() error = %v", runErr)
	}

	worst := map[string]checks.Level{}
	for _, f := range findings {
		if severity(f.Level) >= severity(worst[f.CheckID]) {
			worst[f.CheckID] = f.Level
		}
	}
	for checkID, want := range sc.Expect {
		got, ok := worst[checkID]
		if !ok {
			t.Errorf("%s: no findings, want %s", checkID, want)
			continue
		}
		if string(got) != want {
			t.Errorf("%s: worst level = %s, want %s\n%s", checkID, got, want, findingsOf(findings, checkID))
		}
	}
}

func findingsOf(findings []checks.Finding, checkID string) string {
	var b strings.Builder
	for _, f := range findings {
		if f.CheckID == checkID {
			fmt.Fprintf(&b, "  [%s] %s: %s\n", f.Level, f.Resource, f.Message)
		}
	}
	return b.String()
}

func severity(l checks.Level) int {
	switch l {
	case checks.LevelError:
		return 5
	case checks.LevelWarn:
		return 4
	case checks.LevelUnknown:
		return 3
	case checks.LevelSkip:
		return 2
	case checks.LevelOK:
		return 1
	default:
		return 0
	}
}

func arnTail(arn string) string {
	if i := strings.LastIndexByte(arn, '/'); i >= 0 {
		return arn[i+1:]
	}
	return arn
}

func apiError(code string) error {
	return &smithy.GenericAPIError{Code: code, Message: code}
}

func fakeECS(sc *scenario) *awsapitest.ECS {
	f := &awsapitest.ECS{}
	f.DescribeTasksFn = func(*ecs.DescribeTasksInput) (*ecs.DescribeTasksOutput, error) {
		return &ecs.DescribeTasksOutput{Tasks: []ecstypes.Task{*sc.Task}}, nil
	}
	f.DescribeTaskDefinitionFn = func(*ecs.DescribeTaskDefinitionInput) (*ecs.DescribeTaskDefinitionOutput, error) {
		return &ecs.DescribeTaskDefinitionOutput{TaskDefinition: sc.TaskDefinition}, nil
	}
	f.DescribeClustersFn = func(*ecs.DescribeClustersInput) (*ecs.DescribeClustersOutput, error) {
		if sc.Cluster == nil {
			return &ecs.DescribeClustersOutput{}, nil
		}
		return &ecs.DescribeClustersOutput{Clusters: []ecstypes.Cluster{*sc.Cluster}}, nil
	}
	f.DescribeContainerInstancesFn = func(*ecs.DescribeContainerInstancesInput) (*ecs.DescribeContainerInstancesOutput, error) {
		if sc.ContainerInstance == nil {
			return &ecs.DescribeContainerInstancesOutput{}, nil
		}
		return &ecs.DescribeContainerInstancesOutput{ContainerInstances: []ecstypes.ContainerInstance{*sc.ContainerInstance}}, nil
	}
	return f
}

func fakeSTS(sc *scenario) *awsapitest.STS {
	f := &awsapitest.STS{}
	if sc.Env.CallerArn != "" {
		f.GetCallerIdentityFn = func(*sts.GetCallerIdentityInput) (*sts.GetCallerIdentityOutput, error) {
			return &sts.GetCallerIdentityOutput{
				Account: aws.String("123456789012"),
				Arn:     aws.String(sc.Env.CallerArn),
			}, nil
		}
	}
	return f
}

func fakeIAM(sc *scenario) *awsapitest.IAM {
	f := &awsapitest.IAM{}
	f.SimulatePrincipalPolicyFn = func(in *iam.SimulatePrincipalPolicyInput) (*iam.SimulatePrincipalPolicyOutput, error) {
		out := &iam.SimulatePrincipalPolicyOutput{}
		for _, action := range in.ActionNames {
			result := iamtypes.EvaluationResult{
				EvalActionName: aws.String(action),
				EvalDecision:   iamtypes.PolicyEvaluationDecisionTypeAllowed,
			}
			if contains(sc.Env.DenyActions, action) {
				result.EvalDecision = iamtypes.PolicyEvaluationDecisionTypeImplicitDeny
			}
			if contains(sc.Env.ConditionDenyActions, action) {
				result.EvalDecision = iamtypes.PolicyEvaluationDecisionTypeImplicitDeny
				result.MissingContextValues = []string{"aws:ResourceTag/env"}
			}
			out.EvaluationResults = append(out.EvaluationResults, result)
		}
		return out, nil
	}
	if sc.Env.InstanceProfileRoleArn != "" {
		f.GetInstanceProfileFn = func(*iam.GetInstanceProfileInput) (*iam.GetInstanceProfileOutput, error) {
			return &iam.GetInstanceProfileOutput{InstanceProfile: &iamtypes.InstanceProfile{
				Roles: []iamtypes.Role{{Arn: aws.String(sc.Env.InstanceProfileRoleArn)}},
			}}, nil
		}
	}
	return f
}

func fakeEC2(sc *scenario) *awsapitest.EC2 {
	f := &awsapitest.EC2{}
	if sc.Env.InstanceProfileRoleArn != "" {
		f.DescribeInstancesFn = func(*ec2.DescribeInstancesInput) (*ec2.DescribeInstancesOutput, error) {
			return &ec2.DescribeInstancesOutput{Reservations: []ec2types.Reservation{{
				Instances: []ec2types.Instance{{
					IamInstanceProfile: &ec2types.IamInstanceProfile{
						Arn: aws.String("arn:aws:iam::123456789012:instance-profile/ecs-nodes"),
					},
				}},
			}}}, nil
		}
	}
	if sub := sc.Env.Subnet; sub != nil {
		f.DescribeSubnetsFn = func(*ec2.DescribeSubnetsInput) (*ec2.DescribeSubnetsOutput, error) {
			return &ec2.DescribeSubnetsOutput{Subnets: []ec2types.Subnet{{
				SubnetId:   aws.String(sub.SubnetID),
				VpcId:      aws.String(sub.VpcID),
				Ipv6Native: aws.Bool(sub.IPv6Native),
			}}}, nil
		}
	}
	f.DescribeRouteTablesFn = func(*ec2.DescribeRouteTablesInput) (*ec2.DescribeRouteTablesOutput, error) {
		if sc.Env.PublicRoute == nil {
			return &ec2.DescribeRouteTablesOutput{}, nil
		}
		routes := []ec2types.Route{{
			DestinationCidrBlock: aws.String("10.0.0.0/16"),
			GatewayId:            aws.String("local"),
			State:                ec2types.RouteStateActive,
		}}
		if *sc.Env.PublicRoute {
			routes = append(routes, ec2types.Route{
				DestinationCidrBlock: aws.String("0.0.0.0/0"),
				GatewayId:            aws.String("igw-1"),
				State:                ec2types.RouteStateActive,
			})
		}
		return &ec2.DescribeRouteTablesOutput{RouteTables: []ec2types.RouteTable{{Routes: routes}}}, nil
	}
	f.DescribeVpcEndpointsFn = func(*ec2.DescribeVpcEndpointsInput) (*ec2.DescribeVpcEndpointsOutput, error) {
		out := &ec2.DescribeVpcEndpointsOutput{}
		for _, service := range sc.Env.VPCEndpoints {
			out.VpcEndpoints = append(out.VpcEndpoints, ec2types.VpcEndpoint{
				ServiceName: aws.String(service),
				State:       ec2types.StateAvailable,
			})
		}
		return out, nil
	}
	return f
}

func fakeKMS(sc *scenario) *awsapitest.KMS {
	f := &awsapitest.KMS{}
	f.DescribeKeyFn = func(in *kms.DescribeKeyInput) (*kms.DescribeKeyOutput, error) {
		if sc.Env.KMSKeyMissing {
			return nil, apiError("NotFoundException")
		}
		return &kms.DescribeKeyOutput{KeyMetadata: &kmstypes.KeyMetadata{
			Arn:     aws.String("arn:aws:kms:ap-northeast-1:123456789012:key/" + aws.ToString(in.KeyId)),
			Enabled: !sc.Env.KMSKeyDisabled,
		}}, nil
	}
	return f
}

func fakeLogs(sc *scenario) *awsapitest.CloudWatchLogs {
	f := &awsapitest.CloudWatchLogs{}
	f.DescribeLogGroupsFn = func(in *cloudwatchlogs.DescribeLogGroupsInput) (*cloudwatchlogs.DescribeLogGroupsOutput, error) {
		if !sc.Env.LogGroupExists {
			return &cloudwatchlogs.DescribeLogGroupsOutput{}, nil
		}
		group := logstypes.LogGroup{LogGroupName: in.LogGroupNamePrefix}
		if sc.Env.LogGroupKMSEncrypted {
			group.KmsKeyId = aws.String("arn:aws:kms:ap-northeast-1:123456789012:key/log-key")
		}
		return &cloudwatchlogs.DescribeLogGroupsOutput{LogGroups: []logstypes.LogGroup{group}}, nil
	}
	return f
}

func fakeS3(sc *scenario) *awsapitest.S3 {
	f := &awsapitest.S3{}
	f.HeadBucketFn = func(*s3.HeadBucketInput) (*s3.HeadBucketOutput, error) {
		if !sc.Env.S3BucketExists {
			return nil, apiError("NotFound")
		}
		return &s3.HeadBucketOutput{}, nil
	}
	f.GetBucketEncryptionFn = func(*s3.GetBucketEncryptionInput) (*s3.GetBucketEncryptionOutput, error) {
		if !sc.Env.S3BucketEncrypted {
			return nil, apiError("ServerSideEncryptionConfigurationNotFoundError")
		}
		return &s3.GetBucketEncryptionOutput{
			ServerSideEncryptionConfiguration: &s3types.ServerSideEncryptionConfiguration{},
		}, nil
	}
	return f
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}
