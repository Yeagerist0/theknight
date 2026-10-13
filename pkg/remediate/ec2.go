package remediate

import (
	"fmt"
	"strings"

	"github.com/Yeagerist0/theknight/pkg/rules"
	"github.com/Yeagerist0/theknight/pkg/scanner"
)

func init() {
	register("sg-restrict-ingress-cidr", sgRestrictIngressCIDR)
}

func sgRestrictIngressCIDR(f rules.Finding) (Fix, error) {
	groupID := f.Resource.ID
	groupName, _ := f.Resource.Metadata["group_name"].(string)
	openAll, _ := f.Resource.Metadata["open_all_ports"].(bool)
	openPorts, _ := f.Resource.Metadata["open_ingress_ports"].([]int32)
	ident := SafeIdent(groupName)
	cidrLines := cidrAttrLines(f.Resource)
	cidrText := openCIDRExplanation(f.Resource)

	if openAll {
		tf := fmt.Sprintf(`# Security group %q (%q) allows all protocols and ports from %s
# via a protocol "-1" rule. There's no single safe replacement — split it
# into explicit per-port rules scoped to a trusted CIDR, e.g.:
#
# resource "aws_security_group_rule" "%s_ingress_<port>" {
#   type              = "ingress"
#   security_group_id = %q
#   from_port         = <port>
#   to_port           = <port>
#   protocol          = "tcp"
%s
# }
`, groupID, groupName, cidrText, ident, groupID, commentLines(cidrLines))

		return Fix{
			Finding: f,
			Explanation: fmt.Sprintf(
				"Security group %q (%q) has a protocol -1 rule open to %s — every port is reachable from the internet. There's no single safe replacement; it needs explicit per-port rules scoped to a trusted CIDR.",
				groupID, groupName, cidrText,
			),
			Terraform: tf,
		}, nil
	}

	var blocks []string
	for _, port := range openPorts {
		blocks = append(blocks, fmt.Sprintf(`resource "aws_security_group_rule" "%s_ingress_%d" {
  type              = "ingress"
  security_group_id = %q
  from_port         = %d
  to_port           = %d
  protocol          = "tcp"
%s
}`, ident, port, groupID, port, port, strings.Join(cidrLines, "\n")))
	}

	return Fix{
		Finding: f,
		Explanation: fmt.Sprintf(
			"Security group %q (%q) allows ingress from %s on port(s) %v. Restrict the source CIDR to a known, trusted range instead of the open internet.",
			groupID, groupName, cidrText, openPorts,
		),
		Terraform: strings.Join(blocks, "\n\n") + "\n",
	}, nil
}

// cidrAttrLines returns the cidr_blocks and/or ipv6_cidr_blocks attribute
// lines a generated aws_security_group_rule needs, based on which address
// family the finding actually found open. Getting this wrong in either
// direction is a real failure mode for a tool whose whole point is "ships
// the fix as a PR": emitting only cidr_blocks for a group that's open via
// ::/0 generates Terraform that, once merged, leaves the real IPv6 hole
// untouched -- a fix that looks complete and isn't. Missing metadata falls
// back to IPv4-only, the unconditional behavior before this field existed.
func cidrAttrLines(r scanner.Resource) []string {
	v4, hasV4 := r.Metadata["ipv4_open"].(bool)
	v6, hasV6 := r.Metadata["ipv6_open"].(bool)
	if !hasV4 && !hasV6 {
		v4 = true
	}

	var lines []string
	if v4 {
		lines = append(lines, `  cidr_blocks       = ["YOUR_TRUSTED_CIDR/32"] # TODO: replace with your office/VPN CIDR`)
	}
	if v6 {
		lines = append(lines, `  ipv6_cidr_blocks  = ["YOUR_TRUSTED_IPV6_CIDR/128"] # TODO: replace with your office/VPN IPv6 CIDR`)
	}
	return lines
}

// commentLines prefixes each of lines with "# ", for embedding
// cidrAttrLines' output inside the openAll branch's commented-out example
// block (that whole block is prose the reviewer reads, not live Terraform
// -- see the explicit per-port rules it's pointing at).
func commentLines(lines []string) string {
	commented := make([]string, len(lines))
	for i, l := range lines {
		commented[i] = "#" + l
	}
	return strings.Join(commented, "\n")
}

// openCIDRExplanation mirrors pkg/rules/ec2.go's openCIDRList so the
// remediation's prose (comments and Explanation) names the same address
// family the finding itself described -- a fix referencing "0.0.0.0/0" for
// a group the finding said was open via "::/0" would be confusing on its
// own, even before getting to whether the Terraform is correct.
func openCIDRExplanation(r scanner.Resource) string {
	v4, hasV4 := r.Metadata["ipv4_open"].(bool)
	v6, hasV6 := r.Metadata["ipv6_open"].(bool)
	if !hasV4 && !hasV6 {
		return "0.0.0.0/0"
	}
	switch {
	case v4 && v6:
		return "0.0.0.0/0 and ::/0"
	case v6:
		return "::/0"
	default:
		return "0.0.0.0/0"
	}
}
