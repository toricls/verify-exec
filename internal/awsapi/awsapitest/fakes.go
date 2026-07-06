// Package awsapitest provides function-field fakes for the awsapi
// interfaces. Every method has a benign default so collectors that a
// test does not exercise still resolve instead of panicking.
package awsapitest

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

type ECS struct {
	DescribeTasksFn              func(*ecs.DescribeTasksInput) (*ecs.DescribeTasksOutput, error)
	DescribeTaskDefinitionFn     func(*ecs.DescribeTaskDefinitionInput) (*ecs.DescribeTaskDefinitionOutput, error)
	DescribeClustersFn           func(*ecs.DescribeClustersInput) (*ecs.DescribeClustersOutput, error)
	DescribeContainerInstancesFn func(*ecs.DescribeContainerInstancesInput) (*ecs.DescribeContainerInstancesOutput, error)
}

func (f *ECS) DescribeTasks(_ context.Context, in *ecs.DescribeTasksInput, _ ...func(*ecs.Options)) (*ecs.DescribeTasksOutput, error) {
	if f.DescribeTasksFn == nil {
		return &ecs.DescribeTasksOutput{}, nil
	}
	return f.DescribeTasksFn(in)
}

func (f *ECS) DescribeTaskDefinition(_ context.Context, in *ecs.DescribeTaskDefinitionInput, _ ...func(*ecs.Options)) (*ecs.DescribeTaskDefinitionOutput, error) {
	if f.DescribeTaskDefinitionFn == nil {
		return &ecs.DescribeTaskDefinitionOutput{TaskDefinition: &ecstypes.TaskDefinition{}}, nil
	}
	return f.DescribeTaskDefinitionFn(in)
}

func (f *ECS) DescribeClusters(_ context.Context, in *ecs.DescribeClustersInput, _ ...func(*ecs.Options)) (*ecs.DescribeClustersOutput, error) {
	if f.DescribeClustersFn == nil {
		return &ecs.DescribeClustersOutput{}, nil
	}
	return f.DescribeClustersFn(in)
}

func (f *ECS) DescribeContainerInstances(_ context.Context, in *ecs.DescribeContainerInstancesInput, _ ...func(*ecs.Options)) (*ecs.DescribeContainerInstancesOutput, error) {
	if f.DescribeContainerInstancesFn == nil {
		return &ecs.DescribeContainerInstancesOutput{}, nil
	}
	return f.DescribeContainerInstancesFn(in)
}

type STS struct {
	GetCallerIdentityFn func(*sts.GetCallerIdentityInput) (*sts.GetCallerIdentityOutput, error)
}

func (f *STS) GetCallerIdentity(_ context.Context, in *sts.GetCallerIdentityInput, _ ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
	if f.GetCallerIdentityFn == nil {
		return &sts.GetCallerIdentityOutput{
			Account: aws.String("123456789012"),
			Arn:     aws.String("arn:aws:iam::123456789012:user/tester"),
		}, nil
	}
	return f.GetCallerIdentityFn(in)
}

type IAM struct {
	GetInstanceProfileFn      func(*iam.GetInstanceProfileInput) (*iam.GetInstanceProfileOutput, error)
	SimulatePrincipalPolicyFn func(*iam.SimulatePrincipalPolicyInput) (*iam.SimulatePrincipalPolicyOutput, error)
}

func (f *IAM) GetInstanceProfile(_ context.Context, in *iam.GetInstanceProfileInput, _ ...func(*iam.Options)) (*iam.GetInstanceProfileOutput, error) {
	if f.GetInstanceProfileFn == nil {
		return &iam.GetInstanceProfileOutput{}, nil
	}
	return f.GetInstanceProfileFn(in)
}

func (f *IAM) SimulatePrincipalPolicy(_ context.Context, in *iam.SimulatePrincipalPolicyInput, _ ...func(*iam.Options)) (*iam.SimulatePrincipalPolicyOutput, error) {
	if f.SimulatePrincipalPolicyFn == nil {
		// No evaluation results digests to "allowed".
		return &iam.SimulatePrincipalPolicyOutput{}, nil
	}
	return f.SimulatePrincipalPolicyFn(in)
}

type EC2 struct {
	DescribeInstancesFn    func(*ec2.DescribeInstancesInput) (*ec2.DescribeInstancesOutput, error)
	DescribeSubnetsFn      func(*ec2.DescribeSubnetsInput) (*ec2.DescribeSubnetsOutput, error)
	DescribeRouteTablesFn  func(*ec2.DescribeRouteTablesInput) (*ec2.DescribeRouteTablesOutput, error)
	DescribeVpcEndpointsFn func(*ec2.DescribeVpcEndpointsInput) (*ec2.DescribeVpcEndpointsOutput, error)
}

func (f *EC2) DescribeInstances(_ context.Context, in *ec2.DescribeInstancesInput, _ ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error) {
	if f.DescribeInstancesFn == nil {
		return &ec2.DescribeInstancesOutput{}, nil
	}
	return f.DescribeInstancesFn(in)
}

func (f *EC2) DescribeSubnets(_ context.Context, in *ec2.DescribeSubnetsInput, _ ...func(*ec2.Options)) (*ec2.DescribeSubnetsOutput, error) {
	if f.DescribeSubnetsFn == nil {
		return &ec2.DescribeSubnetsOutput{}, nil
	}
	return f.DescribeSubnetsFn(in)
}

func (f *EC2) DescribeRouteTables(_ context.Context, in *ec2.DescribeRouteTablesInput, _ ...func(*ec2.Options)) (*ec2.DescribeRouteTablesOutput, error) {
	if f.DescribeRouteTablesFn == nil {
		return &ec2.DescribeRouteTablesOutput{}, nil
	}
	return f.DescribeRouteTablesFn(in)
}

func (f *EC2) DescribeVpcEndpoints(_ context.Context, in *ec2.DescribeVpcEndpointsInput, _ ...func(*ec2.Options)) (*ec2.DescribeVpcEndpointsOutput, error) {
	if f.DescribeVpcEndpointsFn == nil {
		return &ec2.DescribeVpcEndpointsOutput{}, nil
	}
	return f.DescribeVpcEndpointsFn(in)
}

type KMS struct {
	DescribeKeyFn func(*kms.DescribeKeyInput) (*kms.DescribeKeyOutput, error)
}

func (f *KMS) DescribeKey(_ context.Context, in *kms.DescribeKeyInput, _ ...func(*kms.Options)) (*kms.DescribeKeyOutput, error) {
	if f.DescribeKeyFn == nil {
		return &kms.DescribeKeyOutput{}, nil
	}
	return f.DescribeKeyFn(in)
}

type CloudWatchLogs struct {
	DescribeLogGroupsFn func(*cloudwatchlogs.DescribeLogGroupsInput) (*cloudwatchlogs.DescribeLogGroupsOutput, error)
}

func (f *CloudWatchLogs) DescribeLogGroups(_ context.Context, in *cloudwatchlogs.DescribeLogGroupsInput, _ ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.DescribeLogGroupsOutput, error) {
	if f.DescribeLogGroupsFn == nil {
		return &cloudwatchlogs.DescribeLogGroupsOutput{}, nil
	}
	return f.DescribeLogGroupsFn(in)
}

type S3 struct {
	HeadBucketFn          func(*s3.HeadBucketInput) (*s3.HeadBucketOutput, error)
	GetBucketEncryptionFn func(*s3.GetBucketEncryptionInput) (*s3.GetBucketEncryptionOutput, error)
}

func (f *S3) HeadBucket(_ context.Context, in *s3.HeadBucketInput, _ ...func(*s3.Options)) (*s3.HeadBucketOutput, error) {
	if f.HeadBucketFn == nil {
		return &s3.HeadBucketOutput{}, nil
	}
	return f.HeadBucketFn(in)
}

func (f *S3) GetBucketEncryption(_ context.Context, in *s3.GetBucketEncryptionInput, _ ...func(*s3.Options)) (*s3.GetBucketEncryptionOutput, error) {
	if f.GetBucketEncryptionFn == nil {
		return &s3.GetBucketEncryptionOutput{}, nil
	}
	return f.GetBucketEncryptionFn(in)
}

// Fakes bundles one fake per awsapi interface.
type Fakes struct {
	ECS  *ECS
	STS  *STS
	IAM  *IAM
	EC2  *EC2
	KMS  *KMS
	Logs *CloudWatchLogs
	S3   *S3
}

func New() *Fakes {
	return &Fakes{
		ECS:  &ECS{},
		STS:  &STS{},
		IAM:  &IAM{},
		EC2:  &EC2{},
		KMS:  &KMS{},
		Logs: &CloudWatchLogs{},
		S3:   &S3{},
	}
}
