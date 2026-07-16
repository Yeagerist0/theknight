package remediate

import (
	"strings"
	"testing"

	"github.com/Yeagerist0/theknight/internal/rules"
	"github.com/Yeagerist0/theknight/internal/scanner"
)

func TestSGRestrictIngressCIDR_SpecificPorts(t *testing.T) {
	f := rules.Finding{
		RuleID:        "sg-open-ingress",
		RemediationID: "sg-restrict-ingress-cidr",
		Resource: scanner.Resource{
			ID:   "sg-0a1b2c3d",
			Type: "aws_security_group",
			Metadata: map[string]any{
				"group_name":         "ssh-open",
				"open_ingress_ports": []int32{22},
				"open_all_ports":     false,
			},
		},
	}

	fix, ok, err := Generate(f)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}
	if !ok {
		t.Fatal("Generate() ok = false, want true")
	}

	if !strings.Contains(fix.Terraform, `security_group_id = "sg-0a1b2c3d"`) {
		t.Errorf("Terraform missing security_group_id:\n%s", fix.Terraform)
	}
	if !strings.Contains(fix.Terraform, "from_port         = 22") {
		t.Errorf("Terraform missing from_port:\n%s", fix.Terraform)
	}
	if !strings.Contains(fix.Terraform, `resource "aws_security_group_rule" "ssh-open_ingress_22"`) {
		t.Errorf("Terraform missing expected resource name:\n%s", fix.Terraform)
	}
}

func TestSGRestrictIngressCIDR_MultiplePorts(t *testing.T) {
	f := rules.Finding{
		RemediationID: "sg-restrict-ingress-cidr",
		Resource: scanner.Resource{
			ID:   "sg-multi",
			Type: "aws_security_group",
			Metadata: map[string]any{
				"group_name":         "db-open",
				"open_ingress_ports": []int32{3306, 5432},
				"open_all_ports":     false,
			},
		},
	}

	fix, ok, err := Generate(f)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}
	if !ok {
		t.Fatal("Generate() ok = false, want true")
	}

	if !strings.Contains(fix.Terraform, "ingress_3306") || !strings.Contains(fix.Terraform, "ingress_5432") {
		t.Errorf("Terraform missing a per-port block:\n%s", fix.Terraform)
	}
}

func TestSGRestrictIngressCIDR_AllPorts(t *testing.T) {
	f := rules.Finding{
		RemediationID: "sg-restrict-ingress-cidr",
		Resource: scanner.Resource{
			ID:   "sg-wide",
			Type: "aws_security_group",
			Metadata: map[string]any{
				"group_name":     "wide-open",
				"open_all_ports": true,
			},
		},
	}

	fix, ok, err := Generate(f)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}
	if !ok {
		t.Fatal("Generate() ok = false, want true")
	}
	if !strings.Contains(fix.Explanation, "protocol -1") {
		t.Errorf("Explanation should call out the protocol -1 rule: %s", fix.Explanation)
	}
}
