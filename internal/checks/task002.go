package checks

import (
	"context"

	"github.com/toricls/verify-exec/internal/collect"
)

// TASK-002: enableExecuteCommand is true on the task.
type task002 struct{}

func NewTask002() Check { return &task002{} }

func (c *task002) ID() string                          { return "TASK-002" }
func (c *task002) Name() string                        { return "Execute command enabled" }
func (c *task002) DependsOn() []collect.Field          { return []collect.Field{collect.FieldTask} }
func (c *task002) Applicable(s *collect.Snapshot) bool { return true }

func (c *task002) Run(ctx context.Context, s *collect.Snapshot) []Finding {
	task, err := s.Task.Get(ctx)
	if err != nil {
		return nil
	}
	resource := taskResource(task)

	if !task.EnableExecuteCommand {
		return []Finding{{
			CheckID:  c.ID(),
			Level:    LevelError,
			Resource: resource,
			Message:  "enableExecuteCommand is false on this task",
			Remediation: "Re-run the task with --enable-execute-command, or update the service " +
				"(aws ecs update-service --enable-execute-command --force-new-deployment). " + docExec,
		}}
	}
	return []Finding{{
		CheckID:  c.ID(),
		Level:    LevelOK,
		Resource: resource,
		Message:  "enableExecuteCommand is true",
	}}
}
