package checks

import (
	"context"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	ecstypes "github.com/aws/aws-sdk-go-v2/service/ecs/types"

	"github.com/toricls/verify-exec/internal/collect"
)

// NET-002: the task has an outbound path to the ssmmessages endpoint:
// either a default route via IGW/NAT, or an ssmmessages VPC endpoint.
//
// Decision table (catalog):
//
//	public route                     → ok
//	no route, ssmmessages endpoint   → ok
//	no route, no endpoint            → error
//	route not verifiable, endpoints known → ok if ssmmessages endpoint
//	  exists, otherwise warn (a route exists but cannot be followed)
//	cannot query at all              → unknown
type net002 struct{}

func NewNet002() Check { return &net002{} }

func (c *net002) ID() string   { return "NET-002" }
func (c *net002) Name() string { return "Outbound path to ssmmessages" }
func (c *net002) DependsOn() []collect.Field {
	return []collect.Field{collect.FieldTask, collect.FieldNetwork}
}

func (c *net002) Applicable(s *collect.Snapshot) bool {
	return resolved(s.Network).Awsvpc
}

func (c *net002) Run(ctx context.Context, s *collect.Snapshot) []Finding {
	network := resolved(s.Network)
	resource := "subnet/" + network.SubnetID
	region := taskRegion(resolved(s.Task))
	endpointService := fmt.Sprintf("com.amazonaws.%s.ssmmessages", region)
	remediation := "Give the subnet a route to the internet (IGW/NAT gateway) or create a " + endpointService +
		" interface VPC endpoint reachable from the task. " + docTroubleshooting

	if network.SubnetErr != nil {
		return []Finding{{
			CheckID:  c.ID(),
			Level:    LevelUnknown,
			Resource: resource,
			Message:  fmt.Sprintf("could not inspect the task subnet (RAM-shared VPC?): %v", network.SubnetErr),
		}}
	}

	hasEndpoint := network.HasEndpoint(endpointService)

	switch {
	case network.HasPublicRoute != nil && *network.HasPublicRoute:
		return []Finding{{
			CheckID:  c.ID(),
			Level:    LevelOK,
			Resource: resource,
			Message:  "the subnet has a default route via an internet/NAT gateway",
		}}
	case network.HasPublicRoute != nil: // determinedly no public route
		if network.EndpointErr != nil {
			return []Finding{{
				CheckID:  c.ID(),
				Level:    LevelUnknown,
				Resource: resource,
				Message:  fmt.Sprintf("no internet route, and VPC endpoints could not be listed: %v", network.EndpointErr),
			}}
		}
		if hasEndpoint {
			return []Finding{{
				CheckID:  c.ID(),
				Level:    LevelOK,
				Resource: resource,
				Message:  "no internet route, but an ssmmessages VPC endpoint exists",
			}}
		}
		return []Finding{{
			CheckID:     c.ID(),
			Level:       LevelError,
			Resource:    resource,
			Message:     "the subnet has no internet route and no ssmmessages VPC endpoint; the SSM agent cannot reach its control channel",
			Remediation: remediation,
		}}
	default: // route could not be determined
		if network.RouteErr != nil {
			return []Finding{{
				CheckID:  c.ID(),
				Level:    LevelUnknown,
				Resource: resource,
				Message:  fmt.Sprintf("could not determine the subnet's outbound route: %v", network.RouteErr),
			}}
		}
		if hasEndpoint {
			return []Finding{{
				CheckID:  c.ID(),
				Level:    LevelOK,
				Resource: resource,
				Message:  fmt.Sprintf("an ssmmessages VPC endpoint exists (%s)", network.RouteNote),
			}}
		}
		message := "cannot verify the outbound path to ssmmessages"
		if network.RouteNote != "" {
			message = fmt.Sprintf("%s: %s", message, network.RouteNote)
		}
		if network.EndpointErr == nil {
			message += "; no ssmmessages VPC endpoint found"
		}
		return []Finding{{
			CheckID:     c.ID(),
			Level:       LevelWarn,
			Resource:    resource,
			Message:     message,
			Remediation: remediation,
		}}
	}
}

// taskRegion extracts the region field from the task ARN
// (arn:aws:ecs:<region>:<account>:task/...).
func taskRegion(task *ecstypes.Task) string {
	parts := strings.SplitN(aws.ToString(task.TaskArn), ":", 5)
	if len(parts) < 5 {
		return ""
	}
	return parts[3]
}
