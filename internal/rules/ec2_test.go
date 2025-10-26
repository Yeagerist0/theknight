package rules

import (
	"testing"

	"github.com/Yeagerist0/theknight/internal/scanner"
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
