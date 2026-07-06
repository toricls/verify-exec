package collect

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	ecstypes "github.com/aws/aws-sdk-go-v2/service/ecs/types"

	"github.com/toricls/verify-exec/internal/awsapi/awsapitest"
)

func awsvpcTask() ecstypes.Task {
	task := runningTask()
	task.Attachments = []ecstypes.Attachment{{
		Type: aws.String("ElasticNetworkInterface"),
		Details: []ecstypes.KeyValuePair{
			{Name: aws.String("networkInterfaceId"), Value: aws.String("eni-1")},
			{Name: aws.String("subnetId"), Value: aws.String("subnet-1")},
		},
	}}
	return task
}

func withSubnet(f *awsapitest.Fakes, ipv6Native bool) {
	f.EC2.DescribeSubnetsFn = func(*ec2.DescribeSubnetsInput) (*ec2.DescribeSubnetsOutput, error) {
		return &ec2.DescribeSubnetsOutput{Subnets: []ec2types.Subnet{{
			SubnetId:   aws.String("subnet-1"),
			VpcId:      aws.String("vpc-1"),
			Ipv6Native: aws.Bool(ipv6Native),
		}}}, nil
	}
}

func routeTable(routes ...ec2types.Route) *ec2.DescribeRouteTablesOutput {
	return &ec2.DescribeRouteTablesOutput{RouteTables: []ec2types.RouteTable{{Routes: routes}}}
}

func collectNetworkWith(t *testing.T, f *awsapitest.Fakes) *NetworkInfo {
	t.Helper()
	s := Collect(context.Background(), depsOf(f), "my-cluster", "abc123")
	network, err := s.Network.Get(context.Background())
	if err != nil {
		t.Fatalf("Network.Get() error = %v", err)
	}
	return network
}

func TestNetworkRouteViaNATGateway(t *testing.T) {
	f := awsapitest.New()
	withTask(f, awsvpcTask())
	withSubnet(f, false)
	f.EC2.DescribeRouteTablesFn = func(*ec2.DescribeRouteTablesInput) (*ec2.DescribeRouteTablesOutput, error) {
		return routeTable(ec2types.Route{
			DestinationCidrBlock: aws.String("0.0.0.0/0"),
			NatGatewayId:         aws.String("nat-1"),
			State:                ec2types.RouteStateActive,
		}), nil
	}

	network := collectNetworkWith(t, f)
	if network.HasPublicRoute == nil || !*network.HasPublicRoute {
		t.Errorf("HasPublicRoute = %v, want true via NAT gateway", network.HasPublicRoute)
	}
}

func TestNetworkIndirectRouteStaysUndetermined(t *testing.T) {
	f := awsapitest.New()
	withTask(f, awsvpcTask())
	withSubnet(f, false)
	f.EC2.DescribeRouteTablesFn = func(*ec2.DescribeRouteTablesInput) (*ec2.DescribeRouteTablesOutput, error) {
		return routeTable(ec2types.Route{
			DestinationCidrBlock: aws.String("0.0.0.0/0"),
			TransitGatewayId:     aws.String("tgw-1"),
			State:                ec2types.RouteStateActive,
		}), nil
	}

	network := collectNetworkWith(t, f)
	if network.HasPublicRoute != nil {
		t.Errorf("HasPublicRoute = %v, want nil for a TGW default route", *network.HasPublicRoute)
	}
	if network.RouteNote == "" {
		t.Error("RouteNote must explain the unverifiable route")
	}
}

func TestNetworkFallsBackToMainRouteTable(t *testing.T) {
	f := awsapitest.New()
	withTask(f, awsvpcTask())
	withSubnet(f, false)
	calls := 0
	f.EC2.DescribeRouteTablesFn = func(in *ec2.DescribeRouteTablesInput) (*ec2.DescribeRouteTablesOutput, error) {
		calls++
		if calls == 1 {
			// No explicit subnet association.
			return &ec2.DescribeRouteTablesOutput{}, nil
		}
		// Main table lookup must filter on the VPC.
		if aws.ToString(in.Filters[0].Name) != "vpc-id" || in.Filters[0].Values[0] != "vpc-1" {
			t.Errorf("main-table lookup filters = %+v", in.Filters)
		}
		return routeTable(ec2types.Route{
			DestinationCidrBlock: aws.String("0.0.0.0/0"),
			GatewayId:            aws.String("igw-1"),
			State:                ec2types.RouteStateActive,
		}), nil
	}

	network := collectNetworkWith(t, f)
	if calls != 2 {
		t.Errorf("DescribeRouteTables calls = %d, want 2 (association then main)", calls)
	}
	if network.HasPublicRoute == nil || !*network.HasPublicRoute {
		t.Errorf("HasPublicRoute = %v, want true via main table", network.HasPublicRoute)
	}
}

func TestNetworkRouteQueryFailure(t *testing.T) {
	f := awsapitest.New()
	withTask(f, awsvpcTask())
	withSubnet(f, false)
	f.EC2.DescribeRouteTablesFn = func(*ec2.DescribeRouteTablesInput) (*ec2.DescribeRouteTablesOutput, error) {
		return nil, errors.New("UnauthorizedOperation")
	}

	network := collectNetworkWith(t, f)
	if network.HasPublicRoute != nil || network.RouteErr == nil {
		t.Errorf("network = %+v, want undetermined route with RouteErr", network)
	}
}

func TestNetworkIPv6OnlySubnet(t *testing.T) {
	f := awsapitest.New()
	withTask(f, awsvpcTask())
	withSubnet(f, true)

	network := collectNetworkWith(t, f)
	if !network.IPv6Only {
		t.Error("IPv6Only = false, want true for an ipv6-native subnet")
	}
}

func TestNetworkSharedSubnetLookupFailure(t *testing.T) {
	f := awsapitest.New()
	withTask(f, awsvpcTask())
	f.EC2.DescribeSubnetsFn = func(*ec2.DescribeSubnetsInput) (*ec2.DescribeSubnetsOutput, error) {
		return nil, errors.New("UnauthorizedOperation")
	}

	network := collectNetworkWith(t, f)
	if network.SubnetErr == nil {
		t.Error("SubnetErr = nil, want an error for an undescribable subnet")
	}
	if !network.Awsvpc || network.SubnetID != "subnet-1" {
		t.Errorf("network = %+v, want awsvpc with subnet ID preserved", network)
	}
}
