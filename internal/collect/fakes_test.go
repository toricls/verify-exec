package collect

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	ecstypes "github.com/aws/aws-sdk-go-v2/service/ecs/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// Function-field fakes with benign defaults so that collectors we are
// not exercising in a given test still resolve instead of panicking.

type fakeECS struct {
	describeTasks              func(*ecs.DescribeTasksInput) (*ecs.DescribeTasksOutput, error)
	describeTaskDefinition     func(*ecs.DescribeTaskDefinitionInput) (*ecs.DescribeTaskDefinitionOutput, error)
	describeClusters           func(*ecs.DescribeClustersInput) (*ecs.DescribeClustersOutput, error)
	describeContainerInstances func(*ecs.DescribeContainerInstancesInput) (*ecs.DescribeContainerInstancesOutput, error)
}

func (f *fakeECS) DescribeTasks(_ context.Context, in *ecs.DescribeTasksInput, _ ...func(*ecs.Options)) (*ecs.DescribeTasksOutput, error) {
	if f.describeTasks == nil {
		return &ecs.DescribeTasksOutput{}, nil
	}
	return f.describeTasks(in)
}

func (f *fakeECS) DescribeTaskDefinition(_ context.Context, in *ecs.DescribeTaskDefinitionInput, _ ...func(*ecs.Options)) (*ecs.DescribeTaskDefinitionOutput, error) {
	if f.describeTaskDefinition == nil {
		return &ecs.DescribeTaskDefinitionOutput{TaskDefinition: &ecstypes.TaskDefinition{}}, nil
	}
	return f.describeTaskDefinition(in)
}

func (f *fakeECS) DescribeClusters(_ context.Context, in *ecs.DescribeClustersInput, _ ...func(*ecs.Options)) (*ecs.DescribeClustersOutput, error) {
	if f.describeClusters == nil {
		return &ecs.DescribeClustersOutput{}, nil
	}
	return f.describeClusters(in)
}

func (f *fakeECS) DescribeContainerInstances(_ context.Context, in *ecs.DescribeContainerInstancesInput, _ ...func(*ecs.Options)) (*ecs.DescribeContainerInstancesOutput, error) {
	if f.describeContainerInstances == nil {
		return &ecs.DescribeContainerInstancesOutput{}, nil
	}
	return f.describeContainerInstances(in)
}

type fakeSTS struct {
	getCallerIdentity func(*sts.GetCallerIdentityInput) (*sts.GetCallerIdentityOutput, error)
}

func (f *fakeSTS) GetCallerIdentity(_ context.Context, in *sts.GetCallerIdentityInput, _ ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
	if f.getCallerIdentity == nil {
		return &sts.GetCallerIdentityOutput{
			Account: aws.String("123456789012"),
			Arn:     aws.String("arn:aws:iam::123456789012:user/tester"),
		}, nil
	}
	return f.getCallerIdentity(in)
}

type fakeIAM struct {
	getInstanceProfile      func(*iam.GetInstanceProfileInput) (*iam.GetInstanceProfileOutput, error)
	simulatePrincipalPolicy func(*iam.SimulatePrincipalPolicyInput) (*iam.SimulatePrincipalPolicyOutput, error)
}

func (f *fakeIAM) GetInstanceProfile(_ context.Context, in *iam.GetInstanceProfileInput, _ ...func(*iam.Options)) (*iam.GetInstanceProfileOutput, error) {
	if f.getInstanceProfile == nil {
		return &iam.GetInstanceProfileOutput{}, nil
	}
	return f.getInstanceProfile(in)
}

func (f *fakeIAM) SimulatePrincipalPolicy(_ context.Context, in *iam.SimulatePrincipalPolicyInput, _ ...func(*iam.Options)) (*iam.SimulatePrincipalPolicyOutput, error) {
	if f.simulatePrincipalPolicy == nil {
		// No evaluation results digests to "allowed".
		return &iam.SimulatePrincipalPolicyOutput{}, nil
	}
	return f.simulatePrincipalPolicy(in)
}

type fakeEC2 struct {
	describeInstances    func(*ec2.DescribeInstancesInput) (*ec2.DescribeInstancesOutput, error)
	describeSubnets      func(*ec2.DescribeSubnetsInput) (*ec2.DescribeSubnetsOutput, error)
	describeRouteTables  func(*ec2.DescribeRouteTablesInput) (*ec2.DescribeRouteTablesOutput, error)
	describeVpcEndpoints func(*ec2.DescribeVpcEndpointsInput) (*ec2.DescribeVpcEndpointsOutput, error)
}

func (f *fakeEC2) DescribeInstances(_ context.Context, in *ec2.DescribeInstancesInput, _ ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error) {
	if f.describeInstances == nil {
		return &ec2.DescribeInstancesOutput{}, nil
	}
	return f.describeInstances(in)
}

func (f *fakeEC2) DescribeSubnets(_ context.Context, in *ec2.DescribeSubnetsInput, _ ...func(*ec2.Options)) (*ec2.DescribeSubnetsOutput, error) {
	if f.describeSubnets == nil {
		return &ec2.DescribeSubnetsOutput{}, nil
	}
	return f.describeSubnets(in)
}

func (f *fakeEC2) DescribeRouteTables(_ context.Context, in *ec2.DescribeRouteTablesInput, _ ...func(*ec2.Options)) (*ec2.DescribeRouteTablesOutput, error) {
	if f.describeRouteTables == nil {
		return &ec2.DescribeRouteTablesOutput{}, nil
	}
	return f.describeRouteTables(in)
}

func (f *fakeEC2) DescribeVpcEndpoints(_ context.Context, in *ec2.DescribeVpcEndpointsInput, _ ...func(*ec2.Options)) (*ec2.DescribeVpcEndpointsOutput, error) {
	if f.describeVpcEndpoints == nil {
		return &ec2.DescribeVpcEndpointsOutput{}, nil
	}
	return f.describeVpcEndpoints(in)
}

type fakeKMS struct {
	describeKey func(*kms.DescribeKeyInput) (*kms.DescribeKeyOutput, error)
}

func (f *fakeKMS) DescribeKey(_ context.Context, in *kms.DescribeKeyInput, _ ...func(*kms.Options)) (*kms.DescribeKeyOutput, error) {
	if f.describeKey == nil {
		return &kms.DescribeKeyOutput{}, nil
	}
	return f.describeKey(in)
}

type fakeLogs struct {
	describeLogGroups func(*cloudwatchlogs.DescribeLogGroupsInput) (*cloudwatchlogs.DescribeLogGroupsOutput, error)
}

func (f *fakeLogs) DescribeLogGroups(_ context.Context, in *cloudwatchlogs.DescribeLogGroupsInput, _ ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.DescribeLogGroupsOutput, error) {
	if f.describeLogGroups == nil {
		return &cloudwatchlogs.DescribeLogGroupsOutput{}, nil
	}
	return f.describeLogGroups(in)
}

type fakeS3 struct {
	headBucket          func(*s3.HeadBucketInput) (*s3.HeadBucketOutput, error)
	getBucketEncryption func(*s3.GetBucketEncryptionInput) (*s3.GetBucketEncryptionOutput, error)
}

func (f *fakeS3) HeadBucket(_ context.Context, in *s3.HeadBucketInput, _ ...func(*s3.Options)) (*s3.HeadBucketOutput, error) {
	if f.headBucket == nil {
		return &s3.HeadBucketOutput{}, nil
	}
	return f.headBucket(in)
}

func (f *fakeS3) GetBucketEncryption(_ context.Context, in *s3.GetBucketEncryptionInput, _ ...func(*s3.Options)) (*s3.GetBucketEncryptionOutput, error) {
	if f.getBucketEncryption == nil {
		return &s3.GetBucketEncryptionOutput{}, nil
	}
	return f.getBucketEncryption(in)
}

type fakes struct {
	ecs  *fakeECS
	sts  *fakeSTS
	iam  *fakeIAM
	ec2  *fakeEC2
	kms  *fakeKMS
	logs *fakeLogs
	s3   *fakeS3
}

func newFakes() *fakes {
	return &fakes{
		ecs:  &fakeECS{},
		sts:  &fakeSTS{},
		iam:  &fakeIAM{},
		ec2:  &fakeEC2{},
		kms:  &fakeKMS{},
		logs: &fakeLogs{},
		s3:   &fakeS3{},
	}
}

func (f *fakes) deps() Deps {
	return Deps{ECS: f.ecs, STS: f.sts, IAM: f.iam, EC2: f.ec2, KMS: f.kms, Logs: f.logs, S3: f.s3}
}
