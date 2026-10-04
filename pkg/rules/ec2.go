package rules

import (
	"fmt"

	"github.com/Yeagerist0/theknight/pkg/scanner"
)

func init() {
	Register(sgOpenIngressRule{})
}

type sgOpenIngressRule struct{}

func (sgOpenIngressRule) ID() string { return "sg-open-ingress" }

func (sgOpenIngressRule) Applies(r scanner.Resource) bool {
	return r.Type == "aws_security_group"
}

func (sgOpenIngressRule) Evaluate(r scanner.Resource) (Finding, bool) {
	openAll, _ := r.Metadata["open_all_ports"].(bool)
	openPorts, _ := r.Metadata["open_ingress_ports"].([]int32)

	if !openAll && len(openPorts) == 0 {
		return Finding{}, false
	}

	groupName, _ := r.Metadata["group_name"].(string)

	// A protocol -1 rule exposes every port, not just the sensitive ones
	// this scanner watches for — a strictly wider blast radius than any
	// specific-port match, so it's weighted higher.
	severity := SeverityHigh
	title := "Security group open to the internet on a sensitive port"
	desc := fmt.Sprintf("Security group %q (%q) allows ingress from %s", r.ID, groupName, openCIDRList(r))
	if openAll {
		severity = SeverityCritical
		title = "Security group open to the internet on all ports"
		desc += " on all ports."
	} else {
		desc += fmt.Sprintf(" on sensitive ports %v.", openPorts)
	}

	return Finding{
		RuleID:        "sg-open-ingress",
		Resource:      r,
		Severity:      severity,
		Title:         title,
		Description:   desc,
		RemediationID: "sg-restrict-ingress-cidr",
	}, true
}

// openCIDRList describes which address family (or both) actually carries
// the open rule, so the finding doesn't claim "0.0.0.0/0" for a group
// that's only reachable via IPv6's ::/0 -- a real, previously-made claim
// a reviewer could act on incorrectly (restricting the IPv4 rule while the
// actual IPv6 hole stays open). Missing metadata (an older scan result, or
// a test fixture that predates this field) falls back to the IPv4-only
// wording this rule used unconditionally before, rather than producing an
// empty or malformed sentence.
func openCIDRList(r scanner.Resource) string {
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
