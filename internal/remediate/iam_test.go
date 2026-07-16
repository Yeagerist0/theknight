package remediate

import (
	"strings"
	"testing"

	"github.com/Yeagerist0/theknight/internal/rules"
	"github.com/Yeagerist0/theknight/internal/scanner"
)

func TestIAMScopeActions(t *testing.T) {
	f := rules.Finding{
		RuleID:        "iam-wildcard-action",
		RemediationID: "iam-scope-actions",
		Resource: scanner.Resource{
			ID:   "arn:aws:iam::123456789012:role/deploy-role",
			Type: "aws_iam_role",
			Metadata: map[string]any{
				"role_name":         "deploy-role",
				"wildcard_policies": []string{"AllowEverything"},
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

	if !strings.Contains(fix.Terraform, "deploy-role") {
		t.Errorf("Terraform missing role name:\n%s", fix.Terraform)
	}
	if !strings.Contains(fix.Terraform, "Access Analyzer") {
		t.Errorf("Terraform missing guidance toward Access Analyzer:\n%s", fix.Terraform)
	}
	if !strings.Contains(fix.Explanation, "AllowEverything") {
		t.Errorf("Explanation missing policy name: %s", fix.Explanation)
	}
}

func TestIAMScopeActions_MissingRoleNameFallsBackToID(t *testing.T) {
	f := rules.Finding{
		RemediationID: "iam-scope-actions",
		Resource:      scanner.Resource{ID: "arn:aws:iam::123456789012:role/fallback-role"},
	}

	fix, ok, err := Generate(f)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}
	if !ok {
		t.Fatal("Generate() ok = false, want true")
	}
	if !strings.Contains(fix.Explanation, "fallback-role") {
		t.Errorf("Explanation should fall back to Resource.ID when role_name metadata is missing: %s", fix.Explanation)
	}
}
