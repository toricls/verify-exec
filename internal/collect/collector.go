package collect

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecs"

	"github.com/toricls/verify-exec/internal/awsapi"
)

type Deps struct {
	ECS  awsapi.ECS
	STS  awsapi.STS
	IAM  awsapi.IAM
	EC2  awsapi.EC2
	KMS  awsapi.KMS
	Logs awsapi.CloudWatchLogs
	S3   awsapi.S3
}

// Collect starts one goroutine per Snapshot field and returns
// immediately; callers wait on individual promises. Dependency graph
// (catalog §7): Task is the root of the task-side fields; Cluster
// feeds ExecLogConfig; CallerIdentity is independent but its
// simulations read Task/ExecLogConfig.
func Collect(ctx context.Context, deps Deps, cluster, taskID string) *Snapshot {
	s := NewSnapshot()

	downstreamCtx, cancelDownstream := context.WithCancelCause(ctx)
	s.downstreamCtx = downstreamCtx

	go collectTask(ctx, deps, s, cluster, taskID, cancelDownstream)
	go collectTaskDefinition(ctx, deps, s)
	go collectCluster(ctx, deps, s, cluster)
	go collectExecLogConfig(ctx, deps, s)
	go collectContainerInstance(ctx, deps, s)
	go collectTaskRole(ctx, deps, s)
	go collectCallerIdentity(ctx, deps, s)
	go collectNetwork(ctx, deps, s)

	return s
}

func collectTask(ctx context.Context, deps Deps, s *Snapshot, cluster, taskID string, cancelDownstream context.CancelCauseFunc) {
	out, err := deps.ECS.DescribeTasks(ctx, &ecs.DescribeTasksInput{
		Cluster: aws.String(cluster),
		Tasks:   []string{taskID},
	})
	if err != nil {
		err = fmt.Errorf("DescribeTasks failed: %w", err)
		cancelDownstream(err)
		s.Task.Complete(nil, err)
		return
	}
	if len(out.Failures) > 0 {
		f := out.Failures[0]
		err = fmt.Errorf("task %q not found in cluster %q: %s %s",
			taskID, cluster, aws.ToString(f.Reason), aws.ToString(f.Detail))
		cancelDownstream(err)
		s.Task.Complete(nil, err)
		return
	}
	if len(out.Tasks) == 0 {
		err = fmt.Errorf("task %q not found in cluster %q", taskID, cluster)
		cancelDownstream(err)
		s.Task.Complete(nil, err)
		return
	}
	task := &out.Tasks[0]

	// Fail-fast: a stopped task makes runtime collectors
	// (TaskRole / ContainerInstance / Network) pointless, so cancel
	// them instead of issuing useless API calls. Cancel BEFORE
	// completing the promise so that anyone who observes the resolved
	// task is guaranteed to observe the cancellation as well (see
	// Snapshot.gate).
	if ClassifyTaskStatus(aws.ToString(task.LastStatus)) == TaskStopping {
		cancelDownstream(ErrTaskNotRunning)
	}
	s.Task.Complete(task, nil)
}

func collectTaskDefinition(ctx context.Context, deps Deps, s *Snapshot) {
	// Deliberately not gated on the stopped-task fail-fast: task
	// definition checks stay meaningful for a stopped task.
	task, err := s.Task.Get(ctx)
	if err != nil {
		s.TaskDefinition.Complete(nil, fmt.Errorf("task definition unavailable: %w", err))
		return
	}
	out, err := deps.ECS.DescribeTaskDefinition(ctx, &ecs.DescribeTaskDefinitionInput{
		TaskDefinition: task.TaskDefinitionArn,
	})
	if err != nil {
		s.TaskDefinition.Complete(nil, fmt.Errorf("DescribeTaskDefinition failed: %w", err))
		return
	}
	if out.TaskDefinition == nil {
		s.TaskDefinition.Complete(nil, fmt.Errorf("DescribeTaskDefinition returned no task definition"))
		return
	}
	s.TaskDefinition.Complete(out.TaskDefinition, nil)
}

func collectContainerInstance(ctx context.Context, deps Deps, s *Snapshot) {
	task, err := s.gate(ctx)
	if err != nil {
		s.ContainerInstance.Complete(nil, err)
		return
	}
	if task.ContainerInstanceArn == nil {
		// Fargate: there is no container instance. Resolve with a nil
		// value (not an error) so dependent checks can settle their
		// applicability.
		s.ContainerInstance.Complete(nil, nil)
		return
	}
	out, err := deps.ECS.DescribeContainerInstances(ctx, &ecs.DescribeContainerInstancesInput{
		Cluster:            task.ClusterArn,
		ContainerInstances: []string{aws.ToString(task.ContainerInstanceArn)},
	})
	if err != nil {
		s.ContainerInstance.Complete(nil, fmt.Errorf("DescribeContainerInstances failed: %w", err))
		return
	}
	if len(out.ContainerInstances) == 0 {
		s.ContainerInstance.Complete(nil, fmt.Errorf("container instance %q not found", aws.ToString(task.ContainerInstanceArn)))
		return
	}
	s.ContainerInstance.Complete(&out.ContainerInstances[0], nil)
}
