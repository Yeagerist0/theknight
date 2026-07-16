package remediate

import (
	"fmt"
	"strings"

	"github.com/Yeagerist0/theknight/internal/rules"
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

	policies, _ := f.Resource.Metadata["wildcard_policies"].([]string)
	policyName := strings.Join(policies, ", ")
	if policyName == "" {
		policyName = "unknown"
	}

	ident := terraformIdent(roleName)

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
