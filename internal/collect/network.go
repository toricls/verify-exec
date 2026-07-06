package collect

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	ecstypes "github.com/aws/aws-sdk-go-v2/service/ecs/types"
)

func collectNetwork(ctx context.Context, deps Deps, s *Snapshot) {
	task, err := s.gate(ctx)
	if err != nil {
		s.Network.Complete(nil, err)
		return
	}

	eniID, subnetID := taskENI(task)
	if eniID == "" && subnetID == "" {
		// bridge/host network mode: the NET checks are not applicable.
		s.Network.Complete(&NetworkInfo{Awsvpc: false}, nil)
		return
	}
	info := &NetworkInfo{Awsvpc: true, ENIID: eniID, SubnetID: subnetID}

	// Subnet: IPv6-only flag and the VPC ID (needed for endpoints).
	subnets, err := deps.EC2.DescribeSubnets(ctx, &ec2.DescribeSubnetsInput{
		SubnetIds: []string{subnetID},
	})
	if err != nil {
		// e.g. a RAM-shared subnet the caller cannot describe: the NET
		// checks degrade to unknown rather than failing the run.
		info.SubnetErr = fmt.Errorf("DescribeSubnets failed: %w", err)
		s.Network.Complete(info, nil)
		return
	}
	if len(subnets.Subnets) == 0 {
		info.SubnetErr = fmt.Errorf("subnet %q not found", subnetID)
		s.Network.Complete(info, nil)
		return
	}
	subnet := subnets.Subnets[0]
	info.VpcID = aws.ToString(subnet.VpcId)
	info.IPv6Only = aws.ToBool(subnet.Ipv6Native)

	resolveRoute(ctx, deps, info)

	endpoints, err := deps.EC2.DescribeVpcEndpoints(ctx, &ec2.DescribeVpcEndpointsInput{
		Filters: []ec2types.Filter{{Name: aws.String("vpc-id"), Values: []string{info.VpcID}}},
	})
	if err != nil {
		info.EndpointErr = fmt.Errorf("DescribeVpcEndpoints failed: %w", err)
	} else {
		for _, ep := range endpoints.VpcEndpoints {
			if ep.State == ec2types.StateAvailable {
				info.VPCEndpoints = append(info.VPCEndpoints, aws.ToString(ep.ServiceName))
			}
		}
	}

	s.Network.Complete(info, nil)
}

// resolveRoute determines whether the subnet has an outbound default
// route via an internet or NAT gateway. It fills HasPublicRoute:
// true/false when determinable, nil (with RouteNote/RouteErr) when not.
func resolveRoute(ctx context.Context, deps Deps, info *NetworkInfo) {
	table, err := routeTableForSubnet(ctx, deps, info.SubnetID, info.VpcID)
	if err != nil {
		info.RouteErr = err
		return
	}
	if table == nil {
		info.RouteErr = fmt.Errorf("no route table found for subnet %q", info.SubnetID)
		return
	}

	var indirect string // a default route we cannot follow (TGW etc.)
	for _, route := range table.Routes {
		if aws.ToString(route.DestinationCidrBlock) != "0.0.0.0/0" &&
			aws.ToString(route.DestinationIpv6CidrBlock) != "::/0" {
			continue
		}
		if route.State != ec2types.RouteStateActive {
			continue
		}
		gw := aws.ToString(route.GatewayId)
		switch {
		case len(gw) > 4 && gw[:4] == "igw-":
			info.HasPublicRoute = aws.Bool(true)
			return
		case aws.ToString(route.NatGatewayId) != "":
			info.HasPublicRoute = aws.Bool(true)
			return
		case aws.ToString(route.TransitGatewayId) != "":
			indirect = "transit gateway"
		case aws.ToString(route.VpcPeeringConnectionId) != "":
			indirect = "VPC peering connection"
		case gw != "" && gw != "local":
			indirect = gw
		case aws.ToString(route.NetworkInterfaceId) != "" || aws.ToString(route.InstanceId) != "":
			indirect = "NAT instance / network interface"
		}
	}
	if indirect != "" {
		// A default route exists but we cannot verify where it leads;
		// leave HasPublicRoute undetermined rather than asserting error.
		info.RouteNote = fmt.Sprintf("default route via %s (reachability not verifiable)", indirect)
		return
	}
	info.HasPublicRoute = aws.Bool(false)
}

func routeTableForSubnet(ctx context.Context, deps Deps, subnetID, vpcID string) (*ec2types.RouteTable, error) {
	// Explicit subnet association first.
	out, err := deps.EC2.DescribeRouteTables(ctx, &ec2.DescribeRouteTablesInput{
		Filters: []ec2types.Filter{{Name: aws.String("association.subnet-id"), Values: []string{subnetID}}},
	})
	if err != nil {
		return nil, fmt.Errorf("DescribeRouteTables failed: %w", err)
	}
	if len(out.RouteTables) > 0 {
		return &out.RouteTables[0], nil
	}
	// Fall back to the VPC main route table.
	out, err = deps.EC2.DescribeRouteTables(ctx, &ec2.DescribeRouteTablesInput{
		Filters: []ec2types.Filter{
			{Name: aws.String("vpc-id"), Values: []string{vpcID}},
			{Name: aws.String("association.main"), Values: []string{"true"}},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("DescribeRouteTables (main) failed: %w", err)
	}
	if len(out.RouteTables) > 0 {
		return &out.RouteTables[0], nil
	}
	return nil, nil
}

// taskENI extracts the ENI and subnet IDs from the task's
// ElasticNetworkInterface attachment (present only in awsvpc mode).
func taskENI(task *ecstypes.Task) (eniID, subnetID string) {
	for _, att := range task.Attachments {
		if aws.ToString(att.Type) != "ElasticNetworkInterface" {
			continue
		}
		for _, kv := range att.Details {
			switch aws.ToString(kv.Name) {
			case "networkInterfaceId":
				eniID = aws.ToString(kv.Value)
			case "subnetId":
				subnetID = aws.ToString(kv.Value)
			}
		}
		return eniID, subnetID
	}
	return "", ""
}
