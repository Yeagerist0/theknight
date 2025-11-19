package rules

import (
	"fmt"

	"github.com/Yeagerist0/theknight/internal/scanner"
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

	desc := fmt.Sprintf("Security group %q (%s) allows ingress from 0.0.0.0/0", r.ID, groupName)
	if openAll {
		desc += " on all ports."
	} else {
		desc += fmt.Sprintf(" on sensitive ports %v.", openPorts)
	}

	return Finding{
		RuleID:        "sg-open-ingress",
		Resource:      r,
		Severity:      SeverityHigh,
		Title:         "Security group open to the internet on a sensitive port",
		Description:   desc,
		RemediationID: "sg-restrict-ingress-cidr",
	}, true
}
