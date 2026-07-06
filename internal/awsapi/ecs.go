// Package awsapi defines narrow interfaces over the aws-sdk-go-v2
// clients so collectors can be tested against mocks.
package awsapi

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/service/ecs"
)

type ECS interface {
	DescribeTasks(ctx context.Context, in *ecs.DescribeTasksInput, optFns ...func(*ecs.Options)) (*ecs.DescribeTasksOutput, error)
	DescribeTaskDefinition(ctx context.Context, in *ecs.DescribeTaskDefinitionInput, optFns ...func(*ecs.Options)) (*ecs.DescribeTaskDefinitionOutput, error)
}
