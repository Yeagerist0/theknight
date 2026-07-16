package scanner

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

type fakeEC2 struct {
	groups []types.SecurityGroup
}

func (f *fakeEC2) DescribeSecurityGroups(ctx context.Context, params *ec2.DescribeSecurityGroupsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error) {
	return &ec2.DescribeSecurityGroupsOutput{SecurityGroups: f.groups}, nil
}

func TestDiscoverSecurityGroups_OpenSensitivePort(t *testing.T) {
	fake := &fakeEC2{
		groups: []types.SecurityGroup{
			{
				GroupId:   aws.String("sg-1"),
				GroupName: aws.String("ssh-open"),
				IpPermissions: []types.IpPermission{
					{
						IpProtocol: aws.String("tcp"),
						FromPort:   aws.Int32(22),
						ToPort:     aws.Int32(22),
						IpRanges:   []types.IpRange{{CidrIp: aws.String("0.0.0.0/0")}},
					},
				},
			},
		},
	}

	resources, err := discoverSecurityGroups(context.Background(), fake, "us-east-1")
	if err != nil {
		t.Fatalf("discoverSecurityGroups() error = %v", err)
	}
	if len(resources) != 1 {
		t.Fatalf("got %d resources, want 1", len(resources))
	}

	r := resources[0]
	ports, _ := r.Metadata["open_ingress_ports"].([]int32)
	if len(ports) != 1 || ports[0] != 22 {
		t.Errorf("open_ingress_ports = %v, want [22]", ports)
	}
	if got := r.Metadata["open_all_ports"]; got != false {
		t.Errorf("open_all_ports = %v, want false", got)
	}
}

func TestDiscoverSecurityGroups_OpenAllPorts(t *testing.T) {
	fake := &fakeEC2{
		groups: []types.SecurityGroup{
			{
				GroupId:   aws.String("sg-2"),
				GroupName: aws.String("wide-open"),
				IpPermissions: []types.IpPermission{
					{
						IpProtocol: aws.String("-1"),
						IpRanges:   []types.IpRange{{CidrIp: aws.String("0.0.0.0/0")}},
					},
				},
			},
		},
	}

	resources, err := discoverSecurityGroups(context.Background(), fake, "us-east-1")
	if err != nil {
		t.Fatalf("discoverSecurityGroups() error = %v", err)
	}
	if got := resources[0].Metadata["open_all_ports"]; got != true {
		t.Errorf("open_all_ports = %v, want true", got)
	}
}

func TestDiscoverSecurityGroups_RestrictedCIDRNotFlagged(t *testing.T) {
	fake := &fakeEC2{
		groups: []types.SecurityGroup{
			{
				GroupId:   aws.String("sg-3"),
				GroupName: aws.String("internal-only"),
				IpPermissions: []types.IpPermission{
					{
						IpProtocol: aws.String("tcp"),
						FromPort:   aws.Int32(22),
						ToPort:     aws.Int32(22),
						IpRanges:   []types.IpRange{{CidrIp: aws.String("10.0.0.0/8")}},
					},
				},
			},
		},
	}

	resources, err := discoverSecurityGroups(context.Background(), fake, "us-east-1")
	if err != nil {
		t.Fatalf("discoverSecurityGroups() error = %v", err)
	}

	r := resources[0]
	ports, _ := r.Metadata["open_ingress_ports"].([]int32)
	if len(ports) != 0 {
		t.Errorf("open_ingress_ports = %v, want empty", ports)
	}
	if got := r.Metadata["open_all_ports"]; got != false {
		t.Errorf("open_all_ports = %v, want false", got)
	}
}
