package rules

import (
	"strings"
	"testing"

	"github.com/Yeagerist0/theknight/pkg/scanner"
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
				"has_wildcard_action":      true,
				"action_wildcard_policies": []string{"AdminAccess"},
				"role_name":                "deploy-role",
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

func TestIAMWildcardResourceRule_Applies(t *testing.T) {
	rule := iamWildcardResourceRule{}

	if !rule.Applies(scanner.Resource{Type: "aws_iam_role"}) {
		t.Error("expected rule to apply to aws_iam_role")
	}
	if rule.Applies(scanner.Resource{Type: "aws_s3_bucket"}) {
		t.Error("expected rule not to apply to aws_s3_bucket")
	}
}

func TestIAMWildcardResourceRule_Evaluate(t *testing.T) {
	rule := iamWildcardResourceRule{}

	tests := []struct {
		name     string
		metadata map[string]any
		want     bool
	}{
		{
			name: "has wildcard resource",
			metadata: map[string]any{
				"has_wildcard_resource":      true,
				"resource_wildcard_policies": []string{"FullAccess"},
				"role_name":                  "data-role",
			},
			want: true,
		},
		{
			name: "scoped resource",
			metadata: map[string]any{
				"has_wildcard_resource": false,
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
			if got && finding.RuleID != "iam-wildcard-resource" {
				t.Errorf("Finding.RuleID = %q, want %q", finding.RuleID, "iam-wildcard-resource")
			}
		})
	}
}

func TestExposureSeverity(t *testing.T) {
	tests := []struct {
		name         string
		metadata     map[string]any
		wantSeverity Severity
		wantNoteText string
	}{
		{
			name:         "not publicly assumable stays High",
			metadata:     map[string]any{"publicly_assumable": false},
			wantSeverity: SeverityHigh,
			wantNoteText: "",
		},
		{
			name:         "missing key defaults to High",
			metadata:     map[string]any{},
			wantSeverity: SeverityHigh,
			wantNoteText: "",
		},
		{
			name:         "publicly assumable escalates to Critical",
			metadata:     map[string]any{"publicly_assumable": true},
			wantSeverity: SeverityCritical,
			wantNoteText: "outside this AWS account",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := scanner.Resource{Metadata: tt.metadata}
			severity, note := exposureSeverity(r)
			if severity != tt.wantSeverity {
				t.Errorf("severity = %v, want %v", severity, tt.wantSeverity)
			}
			if tt.wantNoteText != "" && !strings.Contains(note, tt.wantNoteText) {
				t.Errorf("note = %q, want it to contain %q", note, tt.wantNoteText)
			}
			if tt.wantNoteText == "" && note != "" {
				t.Errorf("note = %q, want empty", note)
			}
		})
	}
}

func TestIAMWildcardActionRule_PubliclyAssumableIsCritical(t *testing.T) {
	rule := iamWildcardActionRule{}
	r := scanner.Resource{
		ID:   "arn:aws:iam::123456789012:role/dangerous-role",
		Type: "aws_iam_role",
		Metadata: map[string]any{
			"has_wildcard_action":      true,
			"action_wildcard_policies": []string{"AdminAccess"},
			"role_name":                "dangerous-role",
			"publicly_assumable":       true,
		},
	}

	finding, ok := rule.Evaluate(r)
	if !ok {
		t.Fatal("Evaluate() matched = false, want true")
	}
	if finding.Severity != SeverityCritical {
		t.Errorf("Severity = %v, want %v", finding.Severity, SeverityCritical)
	}
}
