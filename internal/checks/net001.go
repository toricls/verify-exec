package checks

import (
	"context"
	"fmt"

	"github.com/toricls/verify-exec/internal/collect"
)

// NET-001: the task ENI is not in an IPv6-only subnet (ECS Exec does
// not support IPv6-only).
type net001 struct{}

func NewNet001() Check { return &net001{} }

func (c *net001) ID() string                 { return "NET-001" }
func (c *net001) Name() string               { return "Not IPv6-only" }
func (c *net001) DependsOn() []collect.Field { return []collect.Field{collect.FieldNetwork} }

func (c *net001) Applicable(s *collect.Snapshot) bool {
	return resolved(s.Network).Awsvpc
}

func (c *net001) Run(ctx context.Context, s *collect.Snapshot) []Finding {
	network := resolved(s.Network)
	resource := "subnet/" + network.SubnetID

	if network.SubnetErr != nil {
		return []Finding{{
			CheckID:  c.ID(),
			Level:    LevelUnknown,
			Resource: resource,
			Message:  fmt.Sprintf("could not inspect the task subnet: %v", network.SubnetErr),
		}}
	}
	if network.IPv6Only {
		return []Finding{{
			CheckID:     c.ID(),
			Level:       LevelError,
			Resource:    resource,
			Message:     "the task runs in an IPv6-only subnet; ECS Exec does not support IPv6-only",
			Remediation: "Run the task in a subnet with IPv4 connectivity. " + docExec + "#ecs-exec-considerations",
		}}
	}
	return []Finding{{
		CheckID:  c.ID(),
		Level:    LevelOK,
		Resource: resource,
		Message:  "the task subnet is not IPv6-only",
	}}
}
