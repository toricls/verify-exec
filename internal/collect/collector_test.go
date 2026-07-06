package collect

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	ecstypes "github.com/aws/aws-sdk-go-v2/service/ecs/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"

	"github.com/toricls/verify-exec/internal/awsapi/awsapitest"
)

func depsOf(f *awsapitest.Fakes) Deps {
	return Deps{ECS: f.ECS, STS: f.STS, IAM: f.IAM, EC2: f.EC2, KMS: f.KMS, Logs: f.Logs, S3: f.S3}
}

const (
	testTaskArn    = "arn:aws:ecs:ap-northeast-1:123456789012:task/my-cluster/abc123"
	testTaskDefArn = "arn:aws:ecs:ap-northeast-1:123456789012:task-definition/app:1"
	testClusterArn = "arn:aws:ecs:ap-northeast-1:123456789012:cluster/my-cluster"
)

func runningTask() ecstypes.Task {
	return ecstypes.Task{
		TaskArn:           aws.String(testTaskArn),
		ClusterArn:        aws.String(testClusterArn),
		LastStatus:        aws.String("RUNNING"),
		TaskDefinitionArn: aws.String(testTaskDefArn),
		LaunchType:        ecstypes.LaunchTypeFargate,
	}
}

func withTask(f *awsapitest.Fakes, task ecstypes.Task) {
	f.ECS.DescribeTasksFn = func(*ecs.DescribeTasksInput) (*ecs.DescribeTasksOutput, error) {
		return &ecs.DescribeTasksOutput{Tasks: []ecstypes.Task{task}}, nil
	}
}

func TestCollectResolvesTaskAndTaskDefinition(t *testing.T) {
	f := awsapitest.New()
	withTask(f, runningTask())
	f.ECS.DescribeTaskDefinitionFn = func(in *ecs.DescribeTaskDefinitionInput) (*ecs.DescribeTaskDefinitionOutput, error) {
		if !strings.HasSuffix(aws.ToString(in.TaskDefinition), "task-definition/app:1") {
			t.Errorf("DescribeTaskDefinition called with %q", aws.ToString(in.TaskDefinition))
		}
		return &ecs.DescribeTaskDefinitionOutput{TaskDefinition: &ecstypes.TaskDefinition{
			Family: aws.String("app"),
		}}, nil
	}

	s := Collect(context.Background(), depsOf(f), "my-cluster", "abc123")

	task, err := s.Task.Get(context.Background())
	if err != nil {
		t.Fatalf("Task.Get() error = %v", err)
	}
	if aws.ToString(task.LastStatus) != "RUNNING" {
		t.Errorf("task status = %q", aws.ToString(task.LastStatus))
	}
	taskDef, err := s.TaskDefinition.Get(context.Background())
	if err != nil {
		t.Fatalf("TaskDefinition.Get() error = %v", err)
	}
	if aws.ToString(taskDef.Family) != "app" {
		t.Errorf("task definition family = %q", aws.ToString(taskDef.Family))
	}
}

func TestCollectTaskNotFound(t *testing.T) {
	f := awsapitest.New()
	f.ECS.DescribeTasksFn = func(*ecs.DescribeTasksInput) (*ecs.DescribeTasksOutput, error) {
		return &ecs.DescribeTasksOutput{Failures: []ecstypes.Failure{{
			Arn:    aws.String(testTaskArn),
			Reason: aws.String("MISSING"),
		}}}, nil
	}
	f.ECS.DescribeTaskDefinitionFn = func(*ecs.DescribeTaskDefinitionInput) (*ecs.DescribeTaskDefinitionOutput, error) {
		t.Error("DescribeTaskDefinition must not be called when the task is missing")
		return nil, nil
	}

	s := Collect(context.Background(), depsOf(f), "my-cluster", "abc123")

	if _, err := s.Task.Get(context.Background()); err == nil || !strings.Contains(err.Error(), "MISSING") {
		t.Errorf("Task.Get() error = %v, want MISSING failure", err)
	}
	if _, err := s.TaskDefinition.Get(context.Background()); err == nil {
		t.Error("TaskDefinition.Get() error = nil, want inherited failure")
	}
}

func TestCollectStoppedTaskCancelsDownstream(t *testing.T) {
	f := awsapitest.New()
	task := runningTask()
	task.LastStatus = aws.String("STOPPED")
	withTask(f, task)
	f.ECS.DescribeTaskDefinitionFn = func(*ecs.DescribeTaskDefinitionInput) (*ecs.DescribeTaskDefinitionOutput, error) {
		return &ecs.DescribeTaskDefinitionOutput{TaskDefinition: &ecstypes.TaskDefinition{}}, nil
	}

	s := Collect(context.Background(), depsOf(f), "my-cluster", "abc123")

	if _, err := s.Task.Get(context.Background()); err != nil {
		t.Fatalf("Task.Get() error = %v", err)
	}
	// The runtime collectors resolve with the fail-fast cause.
	for name, wait := range map[string]func() error{
		"TaskRole":          func() error { _, err := s.TaskRole.Get(context.Background()); return err },
		"ContainerInstance": func() error { _, err := s.ContainerInstance.Get(context.Background()); return err },
		"Network":           func() error { _, err := s.Network.Get(context.Background()); return err },
	} {
		if err := wait(); !errors.Is(err, ErrTaskNotRunning) {
			t.Errorf("%s error = %v, want ErrTaskNotRunning", name, err)
		}
	}
	// TaskDefinition is intentionally NOT canceled.
	if _, err := s.TaskDefinition.Get(context.Background()); err != nil {
		t.Errorf("TaskDefinition.Get() error = %v, want nil", err)
	}
}

func TestCollectClusterMissing(t *testing.T) {
	f := awsapitest.New()
	s := Collect(context.Background(), depsOf(f), "my-cluster", "abc123")

	info, err := s.Cluster.Get(context.Background())
	if err != nil {
		t.Fatalf("Cluster.Get() error = %v", err)
	}
	if info.Cluster != nil {
		t.Errorf("Cluster = %+v, want nil (confirmed absent)", info.Cluster)
	}
	if info.Name != "my-cluster" {
		t.Errorf("Name = %q, want my-cluster", info.Name)
	}
	logCfg, err := s.ExecLogConfig.Get(context.Background())
	if err != nil || logCfg.Logging != "" || logCfg.KMSKeyID != "" {
		t.Errorf("ExecLogConfig = %+v, %v; want empty config", logCfg, err)
	}
}

func TestCollectExecLogConfigResolvesKMS(t *testing.T) {
	f := awsapitest.New()
	withTask(f, runningTask())
	f.ECS.DescribeClustersFn = func(*ecs.DescribeClustersInput) (*ecs.DescribeClustersOutput, error) {
		return &ecs.DescribeClustersOutput{Clusters: []ecstypes.Cluster{{
			ClusterName: aws.String("my-cluster"),
			Status:      aws.String("ACTIVE"),
			Configuration: &ecstypes.ClusterConfiguration{
				ExecuteCommandConfiguration: &ecstypes.ExecuteCommandConfiguration{
					KmsKeyId: aws.String("key-1234"),
					Logging:  ecstypes.ExecuteCommandLoggingDefault,
				},
			},
		}}}, nil
	}
	f.KMS.DescribeKeyFn = func(in *kms.DescribeKeyInput) (*kms.DescribeKeyOutput, error) {
		if aws.ToString(in.KeyId) != "key-1234" {
			t.Errorf("DescribeKey called with %q", aws.ToString(in.KeyId))
		}
		return &kms.DescribeKeyOutput{KeyMetadata: &kmstypes.KeyMetadata{
			Arn:     aws.String("arn:aws:kms:ap-northeast-1:123456789012:key/key-1234"),
			Enabled: true,
		}}, nil
	}

	s := Collect(context.Background(), depsOf(f), "my-cluster", "abc123")
	logCfg, err := s.ExecLogConfig.Get(context.Background())
	if err != nil {
		t.Fatalf("ExecLogConfig.Get() error = %v", err)
	}
	if logCfg.KMSKeyID != "key-1234" || logCfg.KMSKey == nil || !logCfg.KMSKey.Enabled {
		t.Errorf("LogConfigInfo = %+v, want enabled key-1234", logCfg)
	}
	if !strings.HasPrefix(logCfg.KMSKeyArn(), "arn:aws:kms:") {
		t.Errorf("KMSKeyArn() = %q, want key ARN", logCfg.KMSKeyArn())
	}
}

func TestCollectTaskRoleFromTaskDefinition(t *testing.T) {
	f := awsapitest.New()
	withTask(f, runningTask())
	f.ECS.DescribeTaskDefinitionFn = func(*ecs.DescribeTaskDefinitionInput) (*ecs.DescribeTaskDefinitionOutput, error) {
		return &ecs.DescribeTaskDefinitionOutput{TaskDefinition: &ecstypes.TaskDefinition{
			TaskRoleArn: aws.String("arn:aws:iam::123456789012:role/app-task-role"),
		}}, nil
	}
	var (
		mu                  sync.Mutex
		simulatedPrincipals []string
	)
	f.IAM.SimulatePrincipalPolicyFn = func(in *iam.SimulatePrincipalPolicyInput) (*iam.SimulatePrincipalPolicyOutput, error) {
		mu.Lock()
		simulatedPrincipals = append(simulatedPrincipals, aws.ToString(in.PolicySourceArn))
		mu.Unlock()
		return &iam.SimulatePrincipalPolicyOutput{EvaluationResults: []iamtypes.EvaluationResult{{
			EvalActionName: aws.String(in.ActionNames[0]),
			EvalDecision:   iamtypes.PolicyEvaluationDecisionTypeAllowed,
		}}}, nil
	}

	s := Collect(context.Background(), depsOf(f), "my-cluster", "abc123")
	role, err := s.TaskRole.Get(context.Background())
	if err != nil {
		t.Fatalf("TaskRole.Get() error = %v", err)
	}
	if role.Source != RoleSourceTaskRole || role.Name != "app-task-role" {
		t.Errorf("role = %+v, want task role app-task-role", role)
	}
	if role.SSMChannel == nil || !role.SSMChannel.Allowed() {
		t.Errorf("SSMChannel = %+v, want allowed", role.SSMChannel)
	}
	// No KMS/CW/S3 configured → no simulations for them.
	if role.KMSDecrypt != nil || role.CWLogs != nil || role.S3Write != nil {
		t.Errorf("unexpected destination simulations: %+v", role)
	}
	// The caller-side collector also simulates (as user/tester); the
	// role-side simulations must have used the task role ARN.
	mu.Lock()
	defer mu.Unlock()
	roleSimulated := false
	for _, p := range simulatedPrincipals {
		if strings.Contains(p, "role/app-task-role") {
			roleSimulated = true
		}
	}
	if !roleSimulated {
		t.Errorf("no simulation used the task role; principals = %v", simulatedPrincipals)
	}
}

func TestCollectTaskRoleFallsBackToInstanceRole(t *testing.T) {
	f := awsapitest.New()
	task := runningTask()
	task.LaunchType = ecstypes.LaunchTypeEc2
	task.ContainerInstanceArn = aws.String("arn:aws:ecs:ap-northeast-1:123456789012:container-instance/my-cluster/ci-1")
	withTask(f, task)
	f.ECS.DescribeContainerInstancesFn = func(*ecs.DescribeContainerInstancesInput) (*ecs.DescribeContainerInstancesOutput, error) {
		return &ecs.DescribeContainerInstancesOutput{ContainerInstances: []ecstypes.ContainerInstance{{
			ContainerInstanceArn: aws.String("arn:aws:ecs:ap-northeast-1:123456789012:container-instance/my-cluster/ci-1"),
			Ec2InstanceId:        aws.String("i-0123456789abcdef0"),
		}}}, nil
	}
	f.EC2.DescribeInstancesFn = func(in *ec2.DescribeInstancesInput) (*ec2.DescribeInstancesOutput, error) {
		if in.InstanceIds[0] != "i-0123456789abcdef0" {
			t.Errorf("DescribeInstances called with %v", in.InstanceIds)
		}
		return &ec2.DescribeInstancesOutput{Reservations: []ec2types.Reservation{{
			Instances: []ec2types.Instance{{
				IamInstanceProfile: &ec2types.IamInstanceProfile{
					Arn: aws.String("arn:aws:iam::123456789012:instance-profile/ecs-nodes"),
				},
			}},
		}}}, nil
	}
	f.IAM.GetInstanceProfileFn = func(in *iam.GetInstanceProfileInput) (*iam.GetInstanceProfileOutput, error) {
		if aws.ToString(in.InstanceProfileName) != "ecs-nodes" {
			t.Errorf("GetInstanceProfile called with %q", aws.ToString(in.InstanceProfileName))
		}
		return &iam.GetInstanceProfileOutput{InstanceProfile: &iamtypes.InstanceProfile{
			Roles: []iamtypes.Role{{Arn: aws.String("arn:aws:iam::123456789012:role/ecs-node-role")}},
		}}, nil
	}

	s := Collect(context.Background(), depsOf(f), "my-cluster", "abc123")
	role, err := s.TaskRole.Get(context.Background())
	if err != nil {
		t.Fatalf("TaskRole.Get() error = %v", err)
	}
	if role.Source != RoleSourceInstanceRole || role.Name != "ecs-node-role" {
		t.Errorf("role = %+v, want instance role ecs-node-role", role)
	}
}

func TestCollectTaskRoleNoneOnFargateWithoutRole(t *testing.T) {
	f := awsapitest.New()
	withTask(f, runningTask()) // Fargate, no task role in the task definition

	s := Collect(context.Background(), depsOf(f), "my-cluster", "abc123")
	role, err := s.TaskRole.Get(context.Background())
	if err != nil {
		t.Fatalf("TaskRole.Get() error = %v", err)
	}
	if role.Source != RoleSourceNone || role.ResolveErr != nil {
		t.Errorf("role = %+v, want RoleSourceNone without error", role)
	}
}

func TestCollectContainerInstanceNilForFargate(t *testing.T) {
	f := awsapitest.New()
	withTask(f, runningTask())

	s := Collect(context.Background(), depsOf(f), "my-cluster", "abc123")
	ci, err := s.ContainerInstance.Get(context.Background())
	if err != nil || ci != nil {
		t.Errorf("ContainerInstance = (%v, %v), want (nil, nil) for Fargate", ci, err)
	}
}

func TestCollectNetworkNonAwsvpc(t *testing.T) {
	f := awsapitest.New()
	withTask(f, runningTask()) // no ENI attachment

	s := Collect(context.Background(), depsOf(f), "my-cluster", "abc123")
	network, err := s.Network.Get(context.Background())
	if err != nil {
		t.Fatalf("Network.Get() error = %v", err)
	}
	if network.Awsvpc {
		t.Errorf("Awsvpc = true, want false without an ENI attachment")
	}
}

func TestCollectNetworkResolvesSubnetRouteAndEndpoints(t *testing.T) {
	f := awsapitest.New()
	task := runningTask()
	task.Attachments = []ecstypes.Attachment{{
		Type: aws.String("ElasticNetworkInterface"),
		Details: []ecstypes.KeyValuePair{
			{Name: aws.String("networkInterfaceId"), Value: aws.String("eni-1")},
			{Name: aws.String("subnetId"), Value: aws.String("subnet-1")},
		},
	}}
	withTask(f, task)
	f.EC2.DescribeSubnetsFn = func(*ec2.DescribeSubnetsInput) (*ec2.DescribeSubnetsOutput, error) {
		return &ec2.DescribeSubnetsOutput{Subnets: []ec2types.Subnet{{
			SubnetId:   aws.String("subnet-1"),
			VpcId:      aws.String("vpc-1"),
			Ipv6Native: aws.Bool(false),
		}}}, nil
	}
	f.EC2.DescribeRouteTablesFn = func(in *ec2.DescribeRouteTablesInput) (*ec2.DescribeRouteTablesOutput, error) {
		return &ec2.DescribeRouteTablesOutput{RouteTables: []ec2types.RouteTable{{
			Routes: []ec2types.Route{{
				DestinationCidrBlock: aws.String("0.0.0.0/0"),
				GatewayId:            aws.String("igw-1"),
				State:                ec2types.RouteStateActive,
			}},
		}}}, nil
	}
	f.EC2.DescribeVpcEndpointsFn = func(*ec2.DescribeVpcEndpointsInput) (*ec2.DescribeVpcEndpointsOutput, error) {
		return &ec2.DescribeVpcEndpointsOutput{VpcEndpoints: []ec2types.VpcEndpoint{{
			ServiceName: aws.String("com.amazonaws.ap-northeast-1.ssmmessages"),
			State:       ec2types.StateAvailable,
		}}}, nil
	}

	s := Collect(context.Background(), depsOf(f), "my-cluster", "abc123")
	network, err := s.Network.Get(context.Background())
	if err != nil {
		t.Fatalf("Network.Get() error = %v", err)
	}
	if !network.Awsvpc || network.SubnetID != "subnet-1" || network.VpcID != "vpc-1" {
		t.Errorf("network = %+v", network)
	}
	if network.HasPublicRoute == nil || !*network.HasPublicRoute {
		t.Errorf("HasPublicRoute = %v, want true", network.HasPublicRoute)
	}
	if !network.HasEndpoint("com.amazonaws.ap-northeast-1.ssmmessages") {
		t.Errorf("endpoints = %v, want ssmmessages endpoint", network.VPCEndpoints)
	}
}
