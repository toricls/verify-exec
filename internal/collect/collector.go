package collect

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecs"

	"github.com/toricls/verify-exec/internal/awsapi"
)

type Deps struct {
	ECS awsapi.ECS
}

// Collect starts one goroutine per Snapshot field and returns
// immediately; callers wait on individual promises. Dependency graph
// (catalog §7): Task is the root, TaskDefinition resolves from it.
func Collect(ctx context.Context, deps Deps, cluster, taskID string) *Snapshot {
	s := NewSnapshot()

	downstreamCtx, cancelDownstream := context.WithCancelCause(ctx)
	s.downstreamCtx = downstreamCtx

	go func() {
		out, err := deps.ECS.DescribeTasks(ctx, &ecs.DescribeTasksInput{
			Cluster: aws.String(cluster),
			Tasks:   []string{taskID},
		})
		if err != nil {
			err = fmt.Errorf("DescribeTasks failed: %w", err)
			s.Task.Complete(nil, err)
			cancelDownstream(err)
			return
		}
		if len(out.Failures) > 0 {
			f := out.Failures[0]
			err = fmt.Errorf("task %q not found in cluster %q: %s %s",
				taskID, cluster, aws.ToString(f.Reason), aws.ToString(f.Detail))
			s.Task.Complete(nil, err)
			cancelDownstream(err)
			return
		}
		if len(out.Tasks) == 0 {
			err = fmt.Errorf("task %q not found in cluster %q", taskID, cluster)
			s.Task.Complete(nil, err)
			cancelDownstream(err)
			return
		}
		task := &out.Tasks[0]
		s.Task.Complete(task, nil)

		// Fail-fast: a stopped task makes runtime collectors
		// (TaskRole / ContainerInstance / Network) pointless, so cancel
		// them instead of issuing useless API calls.
		if ClassifyTaskStatus(aws.ToString(task.LastStatus)) == TaskStopping {
			cancelDownstream(ErrTaskNotRunning)
		}
	}()

	go func() {
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
		s.TaskDefinition.Complete(out.TaskDefinition, nil)
	}()

	return s
}
