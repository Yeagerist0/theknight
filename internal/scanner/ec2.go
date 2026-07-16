package scanner

import (
	"context"
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

// ec2API is the subset of *ec2.Client that discoverSecurityGroups needs.
// Matching the concrete client's method signature lets tests substitute a
// fake instead of hitting AWS.
type ec2API interface {
	DescribeSecurityGroups(ctx context.Context, params *ec2.DescribeSecurityGroupsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error)
}

// sensitiveIngressPorts are the ports most commonly left open by accident:
// remote administration and default database ports.
var sensitiveIngressPorts = []int32{21, 22, 23, 445, 1433, 3306, 3389, 5432, 6379, 9200, 27017}

func discoverSecurityGroups(ctx context.Context, api ec2API, region string) ([]Resource, error) {
	var (
		resources []Resource
		errs      []error
	)

	paginator := ec2.NewDescribeSecurityGroupsPaginator(api, &ec2.DescribeSecurityGroupsInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			errs = append(errs, fmt.Errorf("describing security groups: %w", err))
			break
		}

		for _, sg := range page.SecurityGroups {
			openPorts, openAll := openIngress(sg.IpPermissions)

			resources = append(resources, Resource{
				ID:     aws.ToString(sg.GroupId),
				Type:   "aws_security_group",
				Region: region,
				Metadata: map[string]any{
					"group_name":         aws.ToString(sg.GroupName),
					"open_ingress_ports": openPorts,
					"open_all_ports":     openAll,
				},
			})
		}
	}

	return resources, errors.Join(errs...)
}

// openIngress reports which sensitive ports (and whether all ports) a
// security group's ingress rules expose to 0.0.0.0/0 or ::/0.
func openIngress(perms []types.IpPermission) (openPorts []int32, openAll bool) {
	seen := map[int32]bool{}

	for _, perm := range perms {
		if !hasOpenCIDR(perm) {
			continue
		}

		if aws.ToString(perm.IpProtocol) == "-1" {
			openAll = true
			continue
		}

		from, to := aws.ToInt32(perm.FromPort), aws.ToInt32(perm.ToPort)
		for _, port := range sensitiveIngressPorts {
			if port >= from && port <= to && !seen[port] {
				seen[port] = true
				openPorts = append(openPorts, port)
			}
		}
	}

	return openPorts, openAll
}

func hasOpenCIDR(perm types.IpPermission) bool {
	for _, r := range perm.IpRanges {
		if aws.ToString(r.CidrIp) == "0.0.0.0/0" {
			return true
		}
	}
	for _, r := range perm.Ipv6Ranges {
		if aws.ToString(r.CidrIpv6) == "::/0" {
			return true
		}
	}
	return false
}
