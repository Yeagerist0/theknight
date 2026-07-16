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

	policies, _ := r.Metadata["action_wildcard_policies"].([]string)
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

func init() {
	Register(iamWildcardResourceRule{})
}

type iamWildcardResourceRule struct{}

func (iamWildcardResourceRule) ID() string { return "iam-wildcard-resource" }

func (iamWildcardResourceRule) Applies(r scanner.Resource) bool {
	return r.Type == "aws_iam_role"
}

func (iamWildcardResourceRule) Evaluate(r scanner.Resource) (Finding, bool) {
	hasWildcard, _ := r.Metadata["has_wildcard_resource"].(bool)
	if !hasWildcard {
		return Finding{}, false
	}

	policies, _ := r.Metadata["resource_wildcard_policies"].([]string)
	roleName, _ := r.Metadata["role_name"].(string)
	if roleName == "" {
		roleName = r.ID
	}

	return Finding{
		RuleID:        "iam-wildcard-resource",
		Resource:      r,
		Severity:      SeverityHigh,
		Title:         "IAM role grants wildcard resource permissions",
		Description:   fmt.Sprintf("Role %q has an Allow statement with Resource: \"*\" in policy %s.", roleName, strings.Join(policies, ", ")),
		RemediationID: "iam-scope-resources",
	}, true
}
