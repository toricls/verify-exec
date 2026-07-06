package checks

import (
	"context"
	"fmt"

	"github.com/toricls/verify-exec/internal/collect"
)

// IAM-001: the task's effective role can open the SSM message channels
// the exec session runs over.
type iam001 struct{}

func NewIam001() Check { return &iam001{} }

func (c *iam001) ID() string   { return "IAM-001" }
func (c *iam001) Name() string { return "Task role SSM channel permissions" }
func (c *iam001) DependsOn() []collect.Field {
	return []collect.Field{collect.FieldTaskRole}
}
func (c *iam001) Applicable(s *collect.Snapshot) bool { return true }

func (c *iam001) Run(ctx context.Context, s *collect.Snapshot) []Finding {
	role := resolved(s.TaskRole)
	if f, done := roleUnavailableFinding(c.ID(), role); done {
		return []Finding{f}
	}
	return []Finding{simFinding(
		c.ID(), "role/"+role.Name, "role "+role.Name, role.SSMChannel, LevelError,
		"the ssmmessages channel actions",
		"Attach a policy allowing ssmmessages:CreateControlChannel/CreateDataChannel/OpenControlChannel/OpenDataChannel to the role. "+docExec+"#ecs-exec-enabling-and-using",
	)}
}

// roleUnavailableFinding maps a missing/unresolvable role to a finding
// shared by all role-based IAM checks: unresolvable → unknown; no role
// at all → skip (TDEF-005 reports that as the actual failure).
func roleUnavailableFinding(checkID string, role *collect.IAMRoleInfo) (Finding, bool) {
	switch {
	case role.ResolveErr != nil:
		return Finding{
			CheckID:  checkID,
			Level:    LevelUnknown,
			Resource: "role/unknown",
			Message:  fmt.Sprintf("could not resolve the effective IAM role: %v", role.ResolveErr),
		}, true
	case role.Source == collect.RoleSourceNone:
		return Finding{
			CheckID:  checkID,
			Level:    LevelSkip,
			Resource: "role/none",
			Message:  "no IAM role to evaluate (reported by TDEF-005)",
		}, true
	}
	return Finding{}, false
}
