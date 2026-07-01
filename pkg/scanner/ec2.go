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
			openPorts, openAll, ipv4Open, ipv6Open := openIngress(sg.IpPermissions)

			resources = append(resources, Resource{
				ID:     aws.ToString(sg.GroupId),
				Type:   "aws_security_group",
				Region: region,
				Metadata: map[string]any{
					"group_name":         aws.ToString(sg.GroupName),
					"open_ingress_ports": openPorts,
					"open_all_ports":     openAll,
					// Which address family actually carries the open rule(s):
					// a security group can be reachable from the whole IPv4
					// internet, the whole IPv6 internet, or both, via separate
					// rules, and the fix differs (cidr_blocks vs
					// ipv6_cidr_blocks in the remediation Terraform) -- see
					// pkg/rules/ec2.go and pkg/remediate/ec2.go.
					"ipv4_open": ipv4Open,
					"ipv6_open": ipv6Open,
				},
			})
		}
	}

	return resources, errors.Join(errs...)
}

// openIngress reports which sensitive ports (and whether all ports) a
// security group's ingress rules expose to 0.0.0.0/0 or ::/0, and which of
// those two address families actually carries an open rule.
func openIngress(perms []types.IpPermission) (openPorts []int32, openAll, ipv4Open, ipv6Open bool) {
	seen := map[int32]bool{}

	for _, perm := range perms {
		v4, v6 := hasOpenCIDR(perm)
		if !v4 && !v6 {
			continue
		}

		from, to := aws.ToInt32(perm.FromPort), aws.ToInt32(perm.ToPort)

		// Protocol -1 (AWS console's "All traffic" preset) is the obvious
		// case, but it's not the only way to open every port: "All TCP" /
		// "All UDP" (also offered as presets in the console, and common from
		// a fat-fingered manual rule) set a specific protocol with
		// FromPort/ToPort spanning the full 0-65535 range instead. Both
		// expose every sensitive port this scanner watches for, so both
		// earn the same Critical "all ports" classification -- a rule that
		// only checked for protocol -1 would quietly under-report an
		// All-TCP-open-to-the-internet group as merely "some sensitive
		// ports open". from<=1 tolerates either convention a UI or a
		// hand-written rule might use for "the whole range" (0 or 1).
		if aws.ToString(perm.IpProtocol) == "-1" || (from <= 1 && to >= 65535) {
			openAll = true
			ipv4Open, ipv6Open = ipv4Open || v4, ipv6Open || v6
			continue
		}

		matched := false
		for _, port := range sensitiveIngressPorts {
			if port >= from && port <= to {
				matched = true
				if !seen[port] {
					seen[port] = true
					openPorts = append(openPorts, port)
				}
			}
		}
		if matched {
			ipv4Open, ipv6Open = ipv4Open || v4, ipv6Open || v6
		}
	}

	return openPorts, openAll, ipv4Open, ipv6Open
}

// hasOpenCIDR reports, separately, whether perm's ranges include the
// IPv4-any CIDR (0.0.0.0/0) and/or the IPv6-any CIDR (::/0). A single rule
// can list both (AWS lets one ingress permission carry both an IpRanges and
// an Ipv6Ranges entry), and which one(s) actually apply changes both the
// finding's description and which Terraform attribute (cidr_blocks vs
// ipv6_cidr_blocks) the generated fix needs to touch -- collapsing this
// into one bool previously meant every finding was described and remediated
// as if only IPv4 was ever the open family, even when it wasn't.
func hasOpenCIDR(perm types.IpPermission) (v4, v6 bool) {
	for _, r := range perm.IpRanges {
		if aws.ToString(r.CidrIp) == "0.0.0.0/0" {
			v4 = true
			break
		}
	}
	for _, r := range perm.Ipv6Ranges {
		if aws.ToString(r.CidrIpv6) == "::/0" {
			v6 = true
			break
		}
	}
	return v4, v6
}
