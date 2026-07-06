package checks

import (
	"context"

	ecstypes "github.com/aws/aws-sdk-go-v2/service/ecs/types"

	"github.com/toricls/verify-exec/internal/collect"
)

// TDEF-003: pidMode is not "task" — with a shared PID namespace, only
// one container of the task can be exec'd into.
type tdef003 struct{}

func NewTdef003() Check { return &tdef003{} }

func (c *tdef003) ID() string   { return "TDEF-003" }
func (c *tdef003) Name() string { return "PID namespace not shared" }
func (c *tdef003) DependsOn() []collect.Field {
	return []collect.Field{collect.FieldTaskDefinition}
}
func (c *tdef003) Applicable(s *collect.Snapshot) bool { return true }

func (c *tdef003) Run(ctx context.Context, s *collect.Snapshot) []Finding {
	taskDef := resolved(s.TaskDefinition)
	resource := taskDefResource(taskDef)

	if taskDef.PidMode == ecstypes.PidModeTask {
		return []Finding{{
			CheckID:  c.ID(),
			Level:    LevelWarn,
			Resource: resource,
			Message:  "pidMode is \"task\"; with a shared PID namespace, ECS Exec works against only one container in the task",
			Remediation: "Remove pidMode=task from the task definition if you need to exec into every container. " +
				docExec + "#ecs-exec-considerations",
		}}
	}
	return []Finding{{
		CheckID:  c.ID(),
		Level:    LevelOK,
		Resource: resource,
		Message:  "pidMode is not \"task\"",
	}}
}
