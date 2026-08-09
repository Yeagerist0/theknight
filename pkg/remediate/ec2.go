package remediate

import (
	"fmt"
	"strings"

	"github.com/Yeagerist0/theknight/pkg/rules"
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

	if openAll {
		tf := fmt.Sprintf(`# Security group %q (%q) allows all protocols and ports from 0.0.0.0/0
# via a protocol "-1" rule. There's no single safe replacement — split it
# into explicit per-port rules scoped to a trusted CIDR, e.g.:
#
# resource "aws_security_group_rule" "%s_ingress_<port>" {
#   type              = "ingress"
#   security_group_id = %q
#   from_port         = <port>
#   to_port           = <port>
#   protocol          = "tcp"
#   cidr_blocks       = ["<your trusted CIDR>/32"]
# }
`, groupID, groupName, ident, groupID)

		return Fix{
			Finding: f,
			Explanation: fmt.Sprintf(
				"Security group %q (%q) has a protocol -1 rule open to 0.0.0.0/0 — every port is reachable from the internet. There's no single safe replacement; it needs explicit per-port rules scoped to a trusted CIDR.",
				groupID, groupName,
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
  cidr_blocks       = ["YOUR_TRUSTED_CIDR/32"] # TODO: replace with your office/VPN CIDR
}`, ident, port, groupID, port, port))
	}

	return Fix{
		Finding: f,
		Explanation: fmt.Sprintf(
			"Security group %q (%q) allows ingress from 0.0.0.0/0 on port(s) %v. Restrict the source CIDR to a known, trusted range instead of the open internet.",
			groupID, groupName, openPorts,
		),
		Terraform: strings.Join(blocks, "\n\n") + "\n",
	}, nil
}
