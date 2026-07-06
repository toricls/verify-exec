package checks

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"

	"github.com/toricls/verify-exec/internal/collect"
)

// TASK-001: the task is RUNNING. Starting states are warn, stopping
// states are error (and trigger the fail-fast cancellation of
// downstream collectors).
type task001 struct{}

func NewTask001() Check { return &task001{} }

func (c *task001) ID() string                          { return "TASK-001" }
func (c *task001) Name() string                        { return "Task is running" }
func (c *task001) DependsOn() []collect.Field          { return []collect.Field{collect.FieldTask} }
func (c *task001) Applicable(s *collect.Snapshot) bool { return true }

func (c *task001) Run(ctx context.Context, s *collect.Snapshot) []Finding {
	task, err := s.Task.Get(ctx)
	if err != nil {
		return nil // dependency errors are handled by the runner
	}
	status := aws.ToString(task.LastStatus)
	resource := taskResource(task)

	switch collect.ClassifyTaskStatus(status) {
	case collect.TaskRunning:
		return []Finding{{
			CheckID:  c.ID(),
			Level:    LevelOK,
			Resource: resource,
			Message:  "task is RUNNING",
		}}
	case collect.TaskStarting:
		return []Finding{{
			CheckID:     c.ID(),
			Level:       LevelWarn,
			Resource:    resource,
			Message:     fmt.Sprintf("task is %s (still starting)", status),
			Remediation: "Wait until the task reaches RUNNING, then retry.",
		}}
	default:
		msg := fmt.Sprintf("task is %s; ECS Exec requires a running task", status)
		if reason := aws.ToString(task.StoppedReason); reason != "" {
			msg += fmt.Sprintf(" (stopped reason: %s)", reason)
		}
		return []Finding{{
			CheckID:     c.ID(),
			Level:       LevelError,
			Resource:    resource,
			Message:     msg,
			Remediation: "Start a new task (with execute command enabled) and target it instead. " + docExec,
		}}
	}
}
