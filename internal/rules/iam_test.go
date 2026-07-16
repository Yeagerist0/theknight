package rules

import (
	"testing"

	"github.com/Yeagerist0/theknight/internal/scanner"
)

func TestIAMWildcardActionRule_Applies(t *testing.T) {
	rule := iamWildcardActionRule{}

	if !rule.Applies(scanner.Resource{Type: "aws_iam_role"}) {
		t.Error("expected rule to apply to aws_iam_role")
	}
	if rule.Applies(scanner.Resource{Type: "aws_s3_bucket"}) {
		t.Error("expected rule not to apply to aws_s3_bucket")
	}
}

func TestIAMWildcardActionRule_Evaluate(t *testing.T) {
	rule := iamWildcardActionRule{}

	tests := []struct {
		name     string
		metadata map[string]any
		want     bool
	}{
		{
			name: "has wildcard action",
			metadata: map[string]any{
				"has_wildcard_action": true,
				"wildcard_policies":   []string{"AdminAccess"},
				"role_name":           "deploy-role",
			},
			want: true,
		},
		{
			name: "scoped policy",
			metadata: map[string]any{
				"has_wildcard_action": false,
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := scanner.Resource{ID: "arn:aws:iam::123456789012:role/test", Type: "aws_iam_role", Metadata: tt.metadata}
			finding, got := rule.Evaluate(r)
			if got != tt.want {
				t.Fatalf("Evaluate() matched = %v, want %v", got, tt.want)
			}
			if got && finding.RuleID != "iam-wildcard-action" {
				t.Errorf("Finding.RuleID = %q, want %q", finding.RuleID, "iam-wildcard-action")
			}
		})
	}
}
