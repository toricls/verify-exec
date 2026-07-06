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
	FieldTask           Field = "Task"
	FieldTaskDefinition Field = "TaskDefinition"
	// TODO: FieldCallerIdentity, FieldCluster, FieldExecLogConfig,
	// FieldTaskRole, FieldContainerInstance, FieldNetwork
)

// ErrTaskNotRunning is the cancellation cause used when TASK-001
// determines the task is stopped/stopping. Checks depending on a
// promise canceled with this cause are reported as skip.
var ErrTaskNotRunning = errors.New("task is not running")

// Snapshot is a set of per-field promises rather than a completed
// struct, so each check can evaluate as soon as its own dependencies
// resolve instead of waiting for all collection to finish. It carries
// only the Task / TaskDefinition fields now; the rest will be added
// along with the remaining checks.
type Snapshot struct {
	Task           *Promise[*ecstypes.Task]
	TaskDefinition *Promise[*ecstypes.TaskDefinition]

	// downstreamCtx is canceled (cause ErrTaskNotRunning) when the task
	// turns out to be stopped. Collectors that are pointless for a
	// stopped task (TaskRole, ContainerInstance, Network) must derive
	// from this context; TaskDefinition intentionally does not (static
	// checks stay meaningful for a stopped task).
	downstreamCtx context.Context
}

func NewSnapshot() *Snapshot {
	return &Snapshot{
		Task:           NewPromise[*ecstypes.Task](),
		TaskDefinition: NewPromise[*ecstypes.TaskDefinition](),
	}
}

// Wait blocks until the named field is resolved, returning only the
// resolution error (the value is discarded).
func (s *Snapshot) Wait(ctx context.Context, f Field) error {
	switch f {
	case FieldTask:
		_, err := s.Task.Get(ctx)
		return err
	case FieldTaskDefinition:
		_, err := s.TaskDefinition.Get(ctx)
		return err
	default:
		return fmt.Errorf("unknown snapshot field %q", f)
	}
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
