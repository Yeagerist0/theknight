package rules

import (
	"strings"
	"testing"

	"github.com/Yeagerist0/theknight/pkg/scanner"
)

func TestSGOpenIngressRule_Applies(t *testing.T) {
	rule := sgOpenIngressRule{}

	if !rule.Applies(scanner.Resource{Type: "aws_security_group"}) {
		t.Error("expected rule to apply to aws_security_group")
	}
	if rule.Applies(scanner.Resource{Type: "aws_s3_bucket"}) {
		t.Error("expected rule not to apply to aws_s3_bucket")
	}
}

func TestSGOpenIngressRule_Evaluate(t *testing.T) {
	rule := sgOpenIngressRule{}

	tests := []struct {
		name     string
		metadata map[string]any
		want     bool
	}{
		{
			name:     "open sensitive port",
			metadata: map[string]any{"open_ingress_ports": []int32{22}, "open_all_ports": false},
			want:     true,
		},
		{
			name:     "open all ports",
			metadata: map[string]any{"open_ingress_ports": []int32(nil), "open_all_ports": true},
			want:     true,
		},
		{
			name:     "closed",
			metadata: map[string]any{"open_ingress_ports": []int32(nil), "open_all_ports": false},
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := scanner.Resource{ID: "sg-123", Type: "aws_security_group", Metadata: tt.metadata}
			finding, got := rule.Evaluate(r)
			if got != tt.want {
				t.Fatalf("Evaluate() matched = %v, want %v", got, tt.want)
			}
			if got && finding.RuleID != "sg-open-ingress" {
				t.Errorf("Finding.RuleID = %q, want %q", finding.RuleID, "sg-open-ingress")
			}
		})
	}
}

func TestSGOpenIngressRule_SeverityByExposure(t *testing.T) {
	rule := sgOpenIngressRule{}

	tests := []struct {
		name         string
		metadata     map[string]any
		wantSeverity Severity
	}{
		{
			name:         "specific sensitive port is High",
			metadata:     map[string]any{"open_ingress_ports": []int32{22}, "open_all_ports": false},
			wantSeverity: SeverityHigh,
		},
		{
			name:         "all ports open is Critical",
			metadata:     map[string]any{"open_ingress_ports": []int32(nil), "open_all_ports": true},
			wantSeverity: SeverityCritical,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := scanner.Resource{ID: "sg-123", Type: "aws_security_group", Metadata: tt.metadata}
			finding, ok := rule.Evaluate(r)
			if !ok {
				t.Fatal("Evaluate() matched = false, want true")
			}
			if finding.Severity != tt.wantSeverity {
				t.Errorf("Severity = %v, want %v", finding.Severity, tt.wantSeverity)
			}
		})
	}
}

// TestSGOpenIngressRule_GroupNameIsEscapedInDescription guards against a
// crafted security group name reaching Finding.Description unescaped.
// Description is exposed verbatim via `theknight scan --output json`,
// meant for downstream/programmatic consumption — an unescaped newline or
// quote there is a smaller-blast-radius version of the same problem
// pkg/remediate/ec2.go's Terraform generation has (see that
// package's TestSGRestrictIngressCIDR_GroupNameIsEscaped), so it gets the
// same %q treatment and the same style of regression test.
func TestSGOpenIngressRule_GroupNameIsEscapedInDescription(t *testing.T) {
	malicious := "evil\"\nresource \"aws_iam_role_policy\" \"pwn\" {}"

	r := scanner.Resource{
		ID:   "sg-evil",
		Type: "aws_security_group",
		Metadata: map[string]any{
			"group_name":         malicious,
			"open_ingress_ports": []int32{22},
			"open_all_ports":     false,
		},
	}

	finding, ok := sgOpenIngressRule{}.Evaluate(r)
	if !ok {
		t.Fatal("Evaluate() matched = false, want true")
	}

	for line := range strings.SplitSeq(finding.Description, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, `resource "aws_iam_role_policy" "pwn"`) {
			t.Fatalf("group_name broke out of its string context in Description:\n%s", finding.Description)
		}
	}
}

// TestSGOpenIngressRule_DescribesTheActualOpenFamily is the regression test
// for the gap this fix closes: the Description used to say "0.0.0.0/0"
// unconditionally, even for a group open only via ::/0 -- a reviewer
// reading that would restrict the wrong CIDR family and leave the real
// hole open.
func TestSGOpenIngressRule_DescribesTheActualOpenFamily(t *testing.T) {
	tests := []struct {
		name     string
		ipv4Open bool
		ipv6Open bool
		want     string
		notWant  string
	}{
		{name: "ipv4 only", ipv4Open: true, ipv6Open: false, want: "0.0.0.0/0", notWant: "::/0"},
		{name: "ipv6 only", ipv4Open: false, ipv6Open: true, want: "::/0", notWant: "0.0.0.0/0"},
		{name: "both", ipv4Open: true, ipv6Open: true, want: "0.0.0.0/0 and ::/0"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := scanner.Resource{
				ID:   "sg-123",
				Type: "aws_security_group",
				Metadata: map[string]any{
					"open_ingress_ports": []int32{22},
					"open_all_ports":     false,
					"ipv4_open":          tt.ipv4Open,
					"ipv6_open":          tt.ipv6Open,
				},
			}
			finding, ok := sgOpenIngressRule{}.Evaluate(r)
			if !ok {
				t.Fatal("Evaluate() matched = false, want true")
			}
			if !strings.Contains(finding.Description, tt.want) {
				t.Errorf("Description = %q, want it to contain %q", finding.Description, tt.want)
			}
			if tt.notWant != "" && strings.Contains(finding.Description, tt.notWant) {
				t.Errorf("Description = %q, want it NOT to contain %q", finding.Description, tt.notWant)
			}
		})
	}
}
