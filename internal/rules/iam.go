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

	severity, exposureNote := exposureSeverity(r)

	return Finding{
		RuleID:        "iam-wildcard-action",
		Resource:      r,
		Severity:      severity,
		Title:         "IAM role grants wildcard action permissions",
		Description:   fmt.Sprintf("Role %q has an Allow statement with Action: \"*\" in policy %s.%s", roleName, strings.Join(policies, ", "), exposureNote),
		RemediationID: "iam-scope-actions",
	}, true
}

// exposureSeverity escalates a High wildcard finding to Critical when the
// role's trust policy allows it to be assumed from outside the AWS
// account (or by anyone) — see scanner's roleIsPubliclyAssumable. An
// internally wildcarded role and a publicly assumable one are different
// classes of risk, not just a matter of degree, so this isn't folded into
// the wildcard check itself.
func exposureSeverity(r scanner.Resource) (severity Severity, descriptionSuffix string) {
	if external, _ := r.Metadata["publicly_assumable"].(bool); external {
		return SeverityCritical, " This role's trust policy also allows it to be assumed from outside this AWS account (or by anyone), widening the impact beyond an internal misconfiguration."
	}
	return SeverityHigh, ""
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

	severity, exposureNote := exposureSeverity(r)

	return Finding{
		RuleID:        "iam-wildcard-resource",
		Resource:      r,
		Severity:      severity,
		Title:         "IAM role grants wildcard resource permissions",
		Description:   fmt.Sprintf("Role %q has an Allow statement with Resource: \"*\" in policy %s.%s", roleName, strings.Join(policies, ", "), exposureNote),
		RemediationID: "iam-scope-resources",
	}, true
}
