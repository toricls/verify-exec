package checks

import (
	"context"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"

	"github.com/toricls/verify-exec/internal/collect"
)

// TASK-004: the Fargate platform version supports ECS Exec
// (Linux >= 1.4.0, Windows >= 1.0.0).
type task004 struct{}

func NewTask004() Check { return &task004{} }

func (c *task004) ID() string                 { return "TASK-004" }
func (c *task004) Name() string               { return "Fargate platform version" }
func (c *task004) DependsOn() []collect.Field { return []collect.Field{collect.FieldTask} }

func (c *task004) Applicable(s *collect.Snapshot) bool {
	return isFargate(resolved(s.Task))
}

func (c *task004) Run(ctx context.Context, s *collect.Snapshot) []Finding {
	task := resolved(s.Task)
	resource := taskResource(task)

	pv := aws.ToString(task.PlatformVersion)
	windows := strings.Contains(strings.ToUpper(aws.ToString(task.PlatformFamily)), "WINDOWS")
	minRequired := [3]int{1, 4, 0}
	if windows {
		minRequired = [3]int{1, 0, 0}
	}

	version, ok := parseVersion(pv)
	if !ok {
		return []Finding{{
			CheckID:  c.ID(),
			Level:    LevelUnknown,
			Resource: resource,
			Message:  fmt.Sprintf("could not parse Fargate platform version %q", pv),
		}}
	}
	if !versionAtLeast(version, minRequired) {
		return []Finding{{
			CheckID:  c.ID(),
			Level:    LevelError,
			Resource: resource,
			Message: fmt.Sprintf("Fargate platform version %s does not support ECS Exec (requires %s)",
				pv, formatVersion(minRequired)),
			Remediation: "Update the service/task to platform version LATEST (or at least " +
				formatVersion(minRequired) + ") and redeploy. " + docExec + "#ecs-exec-considerations",
		}}
	}
	return []Finding{{
		CheckID:  c.ID(),
		Level:    LevelOK,
		Resource: resource,
		Message:  fmt.Sprintf("Fargate platform version %s supports ECS Exec (>= %s)", pv, formatVersion(minRequired)),
	}}
}
