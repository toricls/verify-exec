package checks

import (
	"context"
	"fmt"

	"github.com/toricls/verify-exec/internal/collect"
)

// IAM-007: the caller's ssm:StartSession on the task should be DENIED.
// If it is allowed, the caller can bypass ECS Exec (and its audit
// logging) with a raw SSM session — the polarity of this check is
// inverted relative to the other IAM checks.
type iam007 struct{}

func NewIam007() Check { return &iam007{} }

func (c *iam007) ID() string   { return "IAM-007" }
func (c *iam007) Name() string { return "Direct ssm:StartSession denied" }
func (c *iam007) DependsOn() []collect.Field {
	return []collect.Field{collect.FieldCallerIdentity, collect.FieldTask}
}
func (c *iam007) Applicable(s *collect.Snapshot) bool { return true }

func (c *iam007) Run(ctx context.Context, s *collect.Snapshot) []Finding {
	caller := resolved(s.CallerIdentity)
	resource := callerResource(caller)
	outcome := caller.SSMStartSession
	const remediation = "Explicitly deny ssm:StartSession on ECS task resources for interactive users so that exec sessions always go through the audited ecs:ExecuteCommand path. " + docExec + "#ecs-exec-best-practices-limit-access-start-session"

	switch {
	case outcome == nil:
		return []Finding{{
			CheckID:  c.ID(),
			Level:    LevelUnknown,
			Resource: resource,
			Message:  "no simulation result for ssm:StartSession",
		}}
	case outcome.Err != nil:
		return []Finding{{
			CheckID:  c.ID(),
			Level:    LevelUnknown,
			Resource: resource,
			Message:  fmt.Sprintf("could not evaluate ssm:StartSession: %v", outcome.Err),
		}}
	case outcome.Allowed():
		msg := "caller is allowed direct ssm:StartSession on the task; ECS Exec (and its audit logging) can be bypassed"
		if outcome.Note != "" {
			msg += " (" + outcome.Note + ")"
		}
		return []Finding{{
			CheckID:     c.ID(),
			Level:       LevelWarn,
			Resource:    resource,
			Message:     msg,
			Remediation: remediation,
		}}
	case outcome.ConditionDependent():
		return []Finding{{
			CheckID:  c.ID(),
			Level:    LevelUnknown,
			Resource: resource,
			Message:  "ssm:StartSession depends on policy Conditions; cannot statically determine whether direct sessions are blocked",
		}}
	default:
		return []Finding{{
			CheckID:  c.ID(),
			Level:    LevelOK,
			Resource: resource,
			Message:  "direct ssm:StartSession on the task is denied",
		}}
	}
}
