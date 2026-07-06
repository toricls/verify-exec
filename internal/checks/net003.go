package checks

import (
	"context"
	"fmt"

	"github.com/toricls/verify-exec/internal/collect"
)

// NET-003: with KMS session encryption configured and no internet
// route (NET-002 determined the subnet is private), a KMS VPC endpoint
// should exist so the SSM agent can reach KMS.
type net003 struct{}

func NewNet003() Check { return &net003{} }

func (c *net003) ID() string   { return "NET-003" }
func (c *net003) Name() string { return "KMS reachable from private subnet" }
func (c *net003) DependsOn() []collect.Field {
	return []collect.Field{collect.FieldTask, collect.FieldNetwork, collect.FieldExecLogConfig}
}

func (c *net003) Applicable(s *collect.Snapshot) bool {
	if resolved(s.ExecLogConfig).KMSKeyID == "" {
		return false
	}
	network := resolved(s.Network)
	// Only when NET-002 positively determined there is no internet
	// route; an undetermined route stays with NET-002's warn/unknown.
	return network.Awsvpc && network.HasPublicRoute != nil && !*network.HasPublicRoute
}

func (c *net003) Run(ctx context.Context, s *collect.Snapshot) []Finding {
	network := resolved(s.Network)
	resource := "vpc/" + network.VpcID
	endpointService := fmt.Sprintf("com.amazonaws.%s.kms", taskRegion(resolved(s.Task)))

	if network.EndpointErr != nil {
		return []Finding{{
			CheckID:  c.ID(),
			Level:    LevelUnknown,
			Resource: resource,
			Message:  fmt.Sprintf("could not list VPC endpoints: %v", network.EndpointErr),
		}}
	}
	if !network.HasEndpoint(endpointService) {
		return []Finding{{
			CheckID:  c.ID(),
			Level:    LevelWarn,
			Resource: resource,
			Message:  "KMS session encryption is configured but the private subnet has no " + endpointService + " VPC endpoint",
			Remediation: "Create a KMS interface VPC endpoint so the SSM agent can reach KMS from the private subnet. " +
				docTroubleshooting,
		}}
	}
	return []Finding{{
		CheckID:  c.ID(),
		Level:    LevelOK,
		Resource: resource,
		Message:  "a KMS VPC endpoint exists for the private subnet",
	}}
}
