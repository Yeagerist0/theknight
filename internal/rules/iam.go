package rules

import (
	"fmt"
	"strings"

	"github.com/Yeagerist0/theknight/internal/scanner"
)

func init() {
	Register(iamWildcardActionRule{})
}

type iamWildcardActionRule struct{}

func (iamWildcardActionRule) ID() string { return "iam-wildcard-action" }

func (iamWildcardActionRule) Applies(r scanner.Resource) bool {
	return r.Type == "aws_iam_role"
}

func (iamWildcardActionRule) Evaluate(r scanner.Resource) (Finding, bool) {
	hasWildcard, _ := r.Metadata["has_wildcard_action"].(bool)
	if !hasWildcard {
		return Finding{}, false
	}

	policies, _ := r.Metadata["wildcard_policies"].([]string)
	roleName, _ := r.Metadata["role_name"].(string)
	if roleName == "" {
		roleName = r.ID
	}

	return Finding{
		RuleID:        "iam-wildcard-action",
		Resource:      r,
		Severity:      SeverityHigh,
		Title:         "IAM role grants wildcard action permissions",
		Description:   fmt.Sprintf("Role %q has an Allow statement with Action: \"*\" in policy %s.", roleName, strings.Join(policies, ", ")),
		RemediationID: "iam-scope-actions",
	}, true
}
