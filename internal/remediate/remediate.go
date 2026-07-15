// Package remediate maps findings to verified Terraform fix templates and
// (in V1) opens a PR against the customer's infra repo with the fix applied.
package remediate

import "github.com/Yeagerist0/theknight/internal/rules"

// Fix is a Terraform patch that resolves a Finding, plus the human-readable
// explanation that goes in the PR description.
type Fix struct {
	Finding     rules.Finding
	Explanation string
	Diff        string
}

// Generate looks up the remediation template for a finding and renders it
// against the finding's resource attributes.
func Generate(f rules.Finding) (Fix, error) {
	// TODO: template lookup by f.RemediationID, HCL patch generation.
	return Fix{}, nil
}
