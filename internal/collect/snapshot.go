package collect

import (
	"context"
	"errors"
	"fmt"
	"strings"

	ecstypes "github.com/aws/aws-sdk-go-v2/service/ecs/types"
)

// Field names a Snapshot promise. Checks declare their dependencies as
// Fields so the runner can wait for them (and translate fail-fast
// cancellation into skip findings) before invoking Run.
type Field string

const (
	FieldCallerIdentity    Field = "CallerIdentity"
	FieldCluster           Field = "Cluster"
	FieldExecLogConfig     Field = "ExecLogConfig"
	FieldTask              Field = "Task"
	FieldTaskDefinition    Field = "TaskDefinition"
	FieldTaskRole          Field = "TaskRole"
	FieldContainerInstance Field = "ContainerInstance"
	FieldNetwork           Field = "Network"
)

// ErrTaskNotRunning is the cancellation cause used when TASK-001
// determines the task is stopped/stopping. Checks depending on a
// promise canceled with this cause are reported as skip.
var ErrTaskNotRunning = errors.New("task is not running")

// Snapshot is a set of per-field promises rather than a completed
// struct, so each check can evaluate as soon as its own dependencies
// resolve instead of waiting for all collection to finish.
type Snapshot struct {
	CallerIdentity    *Promise[*CallerInfo]
	Cluster           *Promise[*ClusterInfo]
	ExecLogConfig     *Promise[*LogConfigInfo]
	Task              *Promise[*ecstypes.Task]
	TaskDefinition    *Promise[*ecstypes.TaskDefinition]
	TaskRole          *Promise[*IAMRoleInfo]
	ContainerInstance *Promise[*ecstypes.ContainerInstance] // nil value for Fargate tasks
	Network           *Promise[*NetworkInfo]

	// downstreamCtx is canceled (cause ErrTaskNotRunning) when the task
	// turns out to be stopped. Collectors that are pointless for a
	// stopped task (TaskRole, ContainerInstance, Network) gate on this
	// context; TaskDefinition intentionally does not (static checks
	// stay meaningful for a stopped task).
	downstreamCtx context.Context
}

func NewSnapshot() *Snapshot {
	return &Snapshot{
		CallerIdentity:    NewPromise[*CallerInfo](),
		Cluster:           NewPromise[*ClusterInfo](),
		ExecLogConfig:     NewPromise[*LogConfigInfo](),
		Task:              NewPromise[*ecstypes.Task](),
		TaskDefinition:    NewPromise[*ecstypes.TaskDefinition](),
		TaskRole:          NewPromise[*IAMRoleInfo](),
		ContainerInstance: NewPromise[*ecstypes.ContainerInstance](),
		Network:           NewPromise[*NetworkInfo](),
	}
}

// Wait blocks until the named field is resolved, returning only the
// resolution error (the value is discarded).
func (s *Snapshot) Wait(ctx context.Context, f Field) error {
	switch f {
	case FieldCallerIdentity:
		_, err := s.CallerIdentity.Get(ctx)
		return err
	case FieldCluster:
		_, err := s.Cluster.Get(ctx)
		return err
	case FieldExecLogConfig:
		_, err := s.ExecLogConfig.Get(ctx)
		return err
	case FieldTask:
		_, err := s.Task.Get(ctx)
		return err
	case FieldTaskDefinition:
		_, err := s.TaskDefinition.Get(ctx)
		return err
	case FieldTaskRole:
		_, err := s.TaskRole.Get(ctx)
		return err
	case FieldContainerInstance:
		_, err := s.ContainerInstance.Get(ctx)
		return err
	case FieldNetwork:
		_, err := s.Network.Get(ctx)
		return err
	default:
		return fmt.Errorf("unknown snapshot field %q", f)
	}
}

// gate waits for the Task promise and then honors the stopped-task
// fail-fast: it returns ErrTaskNotRunning when the downstream context
// was canceled. Collectors that are pointless for a stopped task call
// this instead of Task.Get.
//
// The task collector cancels downstreamCtx BEFORE completing the Task
// promise, so observing the promise as resolved guarantees the
// cancellation (if any) is visible too — this avoids racing a select
// over two ready channels.
func (s *Snapshot) gate(ctx context.Context) (*ecstypes.Task, error) {
	task, err := s.Task.Get(ctx)
	if err != nil {
		return nil, err
	}
	if cause := context.Cause(s.downstreamCtx); cause != nil {
		return nil, cause
	}
	return task, nil
}

// TaskStatusClass groups ECS task lastStatus values by how TASK-001
// treats them.
type TaskStatusClass int

const (
	// TaskStarting: PROVISIONING / PENDING / ACTIVATING → warn.
	TaskStarting TaskStatusClass = iota
	// TaskRunning: RUNNING → ok.
	TaskRunning
	// TaskStopping: DEACTIVATING and later, STOPPED → error; triggers
	// the fail-fast cancellation of downstream collectors.
	TaskStopping
)

func ClassifyTaskStatus(status string) TaskStatusClass {
	switch strings.ToUpper(status) {
	case "RUNNING":
		return TaskRunning
	case "PROVISIONING", "PENDING", "ACTIVATING":
		return TaskStarting
	default:
		return TaskStopping
	}
}
