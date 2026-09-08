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
	desc := fmt.Sprintf("Security group %q (%q) allows ingress from 0.0.0.0/0", r.ID, groupName)
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
