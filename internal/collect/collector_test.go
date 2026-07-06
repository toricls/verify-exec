package collect

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	ecstypes "github.com/aws/aws-sdk-go-v2/service/ecs/types"
)

type fakeECS struct {
	describeTasks          func(*ecs.DescribeTasksInput) (*ecs.DescribeTasksOutput, error)
	describeTaskDefinition func(*ecs.DescribeTaskDefinitionInput) (*ecs.DescribeTaskDefinitionOutput, error)
}

func (f *fakeECS) DescribeTasks(_ context.Context, in *ecs.DescribeTasksInput, _ ...func(*ecs.Options)) (*ecs.DescribeTasksOutput, error) {
	return f.describeTasks(in)
}

func (f *fakeECS) DescribeTaskDefinition(_ context.Context, in *ecs.DescribeTaskDefinitionInput, _ ...func(*ecs.Options)) (*ecs.DescribeTaskDefinitionOutput, error) {
	return f.describeTaskDefinition(in)
}

func TestCollectResolvesTaskAndTaskDefinition(t *testing.T) {
	api := &fakeECS{
		describeTasks: func(in *ecs.DescribeTasksInput) (*ecs.DescribeTasksOutput, error) {
			if aws.ToString(in.Cluster) != "my-cluster" || in.Tasks[0] != "abc123" {
				t.Errorf("DescribeTasks called with cluster=%q tasks=%v", aws.ToString(in.Cluster), in.Tasks)
			}
			return &ecs.DescribeTasksOutput{Tasks: []ecstypes.Task{{
				TaskArn:           aws.String("arn:aws:ecs:ap-northeast-1:123456789012:task/my-cluster/abc123"),
				LastStatus:        aws.String("RUNNING"),
				TaskDefinitionArn: aws.String("arn:aws:ecs:ap-northeast-1:123456789012:task-definition/app:1"),
			}}}, nil
		},
		describeTaskDefinition: func(in *ecs.DescribeTaskDefinitionInput) (*ecs.DescribeTaskDefinitionOutput, error) {
			if !strings.HasSuffix(aws.ToString(in.TaskDefinition), "task-definition/app:1") {
				t.Errorf("DescribeTaskDefinition called with %q", aws.ToString(in.TaskDefinition))
			}
			return &ecs.DescribeTaskDefinitionOutput{TaskDefinition: &ecstypes.TaskDefinition{
				Family: aws.String("app"),
			}}, nil
		},
	}

	s := Collect(context.Background(), Deps{ECS: api}, "my-cluster", "abc123")

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
	api := &fakeECS{
		describeTasks: func(*ecs.DescribeTasksInput) (*ecs.DescribeTasksOutput, error) {
			return &ecs.DescribeTasksOutput{Failures: []ecstypes.Failure{{
				Arn:    aws.String("arn:aws:ecs:ap-northeast-1:123456789012:task/my-cluster/abc123"),
				Reason: aws.String("MISSING"),
			}}}, nil
		},
		describeTaskDefinition: func(*ecs.DescribeTaskDefinitionInput) (*ecs.DescribeTaskDefinitionOutput, error) {
			t.Error("DescribeTaskDefinition must not be called when the task is missing")
			return nil, nil
		},
	}

	s := Collect(context.Background(), Deps{ECS: api}, "my-cluster", "abc123")

	if _, err := s.Task.Get(context.Background()); err == nil || !strings.Contains(err.Error(), "MISSING") {
		t.Errorf("Task.Get() error = %v, want MISSING failure", err)
	}
	// TaskDefinition inherits the failure instead of calling the API.
	if _, err := s.TaskDefinition.Get(context.Background()); err == nil {
		t.Error("TaskDefinition.Get() error = nil, want inherited failure")
	}
}

func TestCollectStoppedTaskCancelsDownstream(t *testing.T) {
	api := &fakeECS{
		describeTasks: func(*ecs.DescribeTasksInput) (*ecs.DescribeTasksOutput, error) {
			return &ecs.DescribeTasksOutput{Tasks: []ecstypes.Task{{
				TaskArn:           aws.String("arn:aws:ecs:ap-northeast-1:123456789012:task/my-cluster/abc123"),
				LastStatus:        aws.String("STOPPED"),
				TaskDefinitionArn: aws.String("arn:aws:ecs:ap-northeast-1:123456789012:task-definition/app:1"),
			}}}, nil
		},
		describeTaskDefinition: func(*ecs.DescribeTaskDefinitionInput) (*ecs.DescribeTaskDefinitionOutput, error) {
			return &ecs.DescribeTaskDefinitionOutput{TaskDefinition: &ecstypes.TaskDefinition{}}, nil
		},
	}

	s := Collect(context.Background(), Deps{ECS: api}, "my-cluster", "abc123")

	if _, err := s.Task.Get(context.Background()); err != nil {
		t.Fatalf("Task.Get() error = %v", err)
	}
	// Fail-fast: downstream context is canceled with ErrTaskNotRunning;
	// an unresolved promise waited on through it yields the cause.
	p := NewPromise[int]()
	if _, err := p.Get(s.downstreamCtx); !errors.Is(err, ErrTaskNotRunning) {
		t.Errorf("Get(downstreamCtx) error = %v, want ErrTaskNotRunning", err)
	}
	// TaskDefinition is intentionally NOT canceled (static checks stay
	// meaningful for a stopped task).
	if _, err := s.TaskDefinition.Get(context.Background()); err != nil {
		t.Errorf("TaskDefinition.Get() error = %v, want nil", err)
	}
}

func TestClassifyTaskStatus(t *testing.T) {
	tests := []struct {
		status string
		want   TaskStatusClass
	}{
		{"RUNNING", TaskRunning},
		{"PROVISIONING", TaskStarting},
		{"PENDING", TaskStarting},
		{"ACTIVATING", TaskStarting},
		{"DEACTIVATING", TaskStopping},
		{"STOPPING", TaskStopping},
		{"DEPROVISIONING", TaskStopping},
		{"STOPPED", TaskStopping},
		{"DELETED", TaskStopping},
	}
	for _, tt := range tests {
		if got := ClassifyTaskStatus(tt.status); got != tt.want {
			t.Errorf("ClassifyTaskStatus(%q) = %v, want %v", tt.status, got, tt.want)
		}
	}
}
