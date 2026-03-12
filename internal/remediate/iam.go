package remediate

import (
	"fmt"
	"strings"

	"github.com/Yeagerist0/theknight/pkg/rules"
)

func init() {
	register("iam-scope-actions", iamScopeActions)
}

// iamScopeActions deliberately does not try to auto-derive a minimal
// action set: unlike a public S3 bucket, there's no safe default to fall
// back to. Deriving the real minimal set needs runtime data (e.g. IAM
// Access Analyzer's CloudTrail-based policy generation) this scanner
// doesn't have. The template points at that instead of guessing.
func iamScopeActions(f rules.Finding) (Fix, error) {
	roleName, _ := f.Resource.Metadata["role_name"].(string)
	if roleName == "" {
		roleName = f.Resource.ID
	}

	policies, _ := f.Resource.Metadata["action_wildcard_policies"].([]string)
	policyName := strings.Join(policies, ", ")
	if policyName == "" {
		policyName = "unknown"
	}

	ident := SafeIdent(roleName)

	tf := fmt.Sprintf(`# Policy %q on role %q grants "Action": "*". There's no safe way to
# auto-derive the minimal action set from static analysis alone — use IAM
# Access Analyzer's "generate policy based on CloudTrail activity" to find
# the actions this role actually calls, then replace the wildcard:
#
# resource "aws_iam_role_policy" %q {
#   name = %q
#   role = %q
#
#   policy = jsonencode({
#     Version = "2012-10-17"
#     Statement = [{
#       Effect   = "Allow"
#       Action   = ["<replace with the specific actions this role needs>"]
#       Resource = "*"
#     }]
#   })
# }
`, policyName, roleName, ident, policyName, roleName)

	return Fix{
		Finding: f,
		Explanation: fmt.Sprintf(
			"Role %q grants unrestricted Action: \"*\" via policy %q. Unlike a public S3 bucket, there's no automated fix that's safe to apply blindly here — the minimal action set depends on what the role actually does. This template points at IAM Access Analyzer's CloudTrail-based policy generation as the next step.",
			roleName, policyName,
		),
		Terraform: tf,
	}, nil
}

func init() {
	register("iam-scope-resources", iamScopeResources)
}

// iamScopeResources mirrors iamScopeActions: there's no safe static default
// for which specific ARNs a role's policy should be scoped to, so this
// points at the same CloudTrail-based generation path rather than guessing.
func iamScopeResources(f rules.Finding) (Fix, error) {
	roleName, _ := f.Resource.Metadata["role_name"].(string)
	if roleName == "" {
		roleName = f.Resource.ID
	}

	policies, _ := f.Resource.Metadata["resource_wildcard_policies"].([]string)
	policyName := strings.Join(policies, ", ")
	if policyName == "" {
		policyName = "unknown"
	}

	ident := SafeIdent(roleName)

	tf := fmt.Sprintf(`# Policy %q on role %q grants "Resource": "*" — the actions it allows can
# target any resource in the account, not just the ones this role needs.
# There's no safe way to auto-derive the correct ARNs from static analysis
# alone — use IAM Access Analyzer's "generate policy based on CloudTrail
# activity" to find which resources this role actually touches, then
# replace the wildcard:
#
# resource "aws_iam_role_policy" %q {
#   name = %q
#   role = %q
#
#   policy = jsonencode({
#     Version = "2012-10-17"
#     Statement = [{
#       Effect   = "Allow"
#       Action   = "<unchanged>"
#       Resource = ["<replace with the specific ARNs this role needs>"]
#     }]
#   })
# }
`, policyName, roleName, ident, policyName, roleName)

	return Fix{
		Finding: f,
		Explanation: fmt.Sprintf(
			"Role %q grants unrestricted Resource: \"*\" via policy %q — its allowed actions can reach any resource in the account. As with a wildcard action, there's no automated fix safe to apply blindly; this template points at IAM Access Analyzer's CloudTrail-based policy generation as the next step.",
			roleName, policyName,
		),
		Terraform: tf,
	}, nil
}
