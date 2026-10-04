package remediate

import (
	"strings"
	"testing"

	"github.com/Yeagerist0/theknight/pkg/rules"
	"github.com/Yeagerist0/theknight/pkg/scanner"
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

// TestSGRestrictIngressCIDR_IPv6OnlyUsesIpv6CidrBlocks is the regression
// test for the gap this fix closes: the generated Terraform used to emit
// cidr_blocks unconditionally, even for a group open only via ::/0.
// cidr_blocks and ipv6_cidr_blocks are different Terraform attributes --
// applying a fix that only sets cidr_blocks against a group whose real
// problem is an open ::/0 rule changes nothing about the actual exposure.
func TestSGRestrictIngressCIDR_IPv6OnlyUsesIpv6CidrBlocks(t *testing.T) {
	f := rules.Finding{
		RuleID:        "sg-open-ingress",
		RemediationID: "sg-restrict-ingress-cidr",
		Resource: scanner.Resource{
			ID:   "sg-ipv6only",
			Type: "aws_security_group",
			Metadata: map[string]any{
				"group_name":         "ipv6-ssh-open",
				"open_ingress_ports": []int32{22},
				"open_all_ports":     false,
				"ipv4_open":          false,
				"ipv6_open":          true,
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
	if !strings.Contains(fix.Terraform, "ipv6_cidr_blocks") {
		t.Errorf("Terraform missing ipv6_cidr_blocks for an IPv6-only finding:\n%s", fix.Terraform)
	}
	if strings.Contains(fix.Terraform, "cidr_blocks       =") {
		t.Errorf("Terraform sets IPv4 cidr_blocks for a finding that is not open via IPv4:\n%s", fix.Terraform)
	}
	if !strings.Contains(fix.Explanation, "::/0") {
		t.Errorf("Explanation should name ::/0, not claim 0.0.0.0/0: %s", fix.Explanation)
	}
}

// TestSGRestrictIngressCIDR_DualStackSetsBothAttributes checks a group open
// via both families gets both Terraform attributes, not just one.
func TestSGRestrictIngressCIDR_DualStackSetsBothAttributes(t *testing.T) {
	f := rules.Finding{
		RuleID:        "sg-open-ingress",
		RemediationID: "sg-restrict-ingress-cidr",
		Resource: scanner.Resource{
			ID:   "sg-dualstack",
			Type: "aws_security_group",
			Metadata: map[string]any{
				"group_name":         "dual-stack-open",
				"open_ingress_ports": []int32{22},
				"open_all_ports":     false,
				"ipv4_open":          true,
				"ipv6_open":          true,
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
	if !strings.Contains(fix.Terraform, "cidr_blocks       =") {
		t.Errorf("Terraform missing IPv4 cidr_blocks for a dual-stack finding:\n%s", fix.Terraform)
	}
	if !strings.Contains(fix.Terraform, "ipv6_cidr_blocks") {
		t.Errorf("Terraform missing ipv6_cidr_blocks for a dual-stack finding:\n%s", fix.Terraform)
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

// TestSGRestrictIngressCIDR_GroupNameIsEscaped guards against HCL
// injection via a security group's Name tag/field. EC2 GroupName
// validation is looser than S3 bucket names or IAM role/policy names (it
// permits spaces and several punctuation characters), and this scanner
// also targets LocalStack in its test suite, which doesn't necessarily
// enforce AWS's server-side name validation identically — so a crafted
// name reaching this far isn't something the template can assume away.
// group_name must always be embedded via %q (Go's escaping turns an
// embedded quote or newline into a visible \" / \n escape sequence,
// keeping it a single-line, inert string value) rather than raw %s.
func TestSGRestrictIngressCIDR_GroupNameIsEscaped(t *testing.T) {
	malicious := "evil\"\n# comment\nresource \"aws_iam_role_policy\" \"pwn\" { role = \"admin\" policy = \"{}\" }"

	f := rules.Finding{
		RemediationID: "sg-restrict-ingress-cidr",
		Resource: scanner.Resource{
			ID:   "sg-evil",
			Type: "aws_security_group",
			Metadata: map[string]any{
				"group_name":         malicious,
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

	for line := range strings.SplitSeq(fix.Terraform, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, `resource "aws_iam_role_policy" "pwn"`) {
			t.Fatalf("group_name broke out of its string context and injected a live top-level resource block:\n%s", fix.Terraform)
		}
	}

	for line := range strings.SplitSeq(fix.Explanation, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, `resource "aws_iam_role_policy" "pwn"`) {
			t.Fatalf("group_name broke out of its string context in Explanation:\n%s", fix.Explanation)
		}
	}
}

func TestSGRestrictIngressCIDR_AllPorts_GroupNameIsEscaped(t *testing.T) {
	malicious := "evil\"\nresource \"aws_iam_role_policy\" \"pwn\" {}"

	f := rules.Finding{
		RemediationID: "sg-restrict-ingress-cidr",
		Resource: scanner.Resource{
			ID:   "sg-evil-all",
			Type: "aws_security_group",
			Metadata: map[string]any{
				"group_name":     malicious,
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

	for line := range strings.SplitSeq(fix.Terraform, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, `resource "aws_iam_role_policy" "pwn"`) {
			t.Fatalf("group_name broke out of its comment context (openAll path) and injected a live resource block:\n%s", fix.Terraform)
		}
	}
}
