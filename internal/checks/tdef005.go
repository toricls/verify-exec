package checks

import (
	"context"
	"fmt"

	"github.com/toricls/verify-exec/internal/collect"
)

// TDEF-005: an IAM role is available to the task. A missing task role
// falls back to the EC2 instance role, so only "both missing" is an
// error.
type tdef005 struct{}

func NewTdef005() Check { return &tdef005{} }

func (c *tdef005) ID() string   { return "TDEF-005" }
func (c *tdef005) Name() string { return "Task role available" }
func (c *tdef005) DependsOn() []collect.Field {
	return []collect.Field{collect.FieldTask, collect.FieldTaskRole}
}
func (c *tdef005) Applicable(s *collect.Snapshot) bool { return true }

func (c *tdef005) Run(ctx context.Context, s *collect.Snapshot) []Finding {
	role := resolved(s.TaskRole)
	resource := taskResource(resolved(s.Task))

	switch {
	case role.ResolveErr != nil:
		return []Finding{{
			CheckID:  c.ID(),
			Level:    LevelUnknown,
			Resource: resource,
			Message:  fmt.Sprintf("could not resolve the effective IAM role: %v", role.ResolveErr),
		}}
	case role.Source == collect.RoleSourceTaskRole:
		return []Finding{{
			CheckID:  c.ID(),
			Level:    LevelOK,
			Resource: resource,
			Message:  fmt.Sprintf("task role %s is set", role.Name),
		}}
	case role.Source == collect.RoleSourceInstanceRole:
		return []Finding{{
			CheckID:  c.ID(),
			Level:    LevelOK,
			Resource: resource,
			Message:  fmt.Sprintf("no task role, but the container instance role %s applies", role.Name),
		}}
	default:
		return []Finding{{
			CheckID:  c.ID(),
			Level:    LevelError,
			Resource: resource,
			Message:  "no task role is set and no instance role is available; the SSM agent has no credentials",
			Remediation: "Set a taskRoleArn with the required ssmmessages permissions in the task definition. " +
				docExec + "#ecs-exec-enabling-and-using",
		}}
	}
}
