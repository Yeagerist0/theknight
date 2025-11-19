// Package rules evaluates scanned resources against misconfiguration
// patterns (public S3 buckets, over-permissioned IAM roles, open security
// groups, ...) and produces prioritized Findings.
package rules

import "github.com/Yeagerist0/theknight/internal/scanner"

type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
)

// Finding is a single detected misconfiguration, tied back to the resource
// it was found on and (eventually) a remediation template ID.
type Finding struct {
	RuleID        string
	Resource      scanner.Resource
	Severity      Severity
	Title         string
	Description   string
	RemediationID string
}

// Rule inspects a single resource and returns a Finding if it matches.
type Rule interface {
	ID() string
	Applies(r scanner.Resource) bool
	Evaluate(r scanner.Resource) (Finding, bool)
}

// Evaluate runs every registered rule against every resource.
func Evaluate(resources []scanner.Resource) []Finding {
	var findings []Finding
	for _, r := range resources {
		for _, rule := range registry {
			if !rule.Applies(r) {
				continue
			}
			if f, ok := rule.Evaluate(r); ok {
				findings = append(findings, f)
			}
		}
	}
	return findings
}

var registry []Rule

// Register adds a rule to the default registry. Rule implementations call
// this from an init() in their own file, so adding a new check never
// requires touching this package.
func Register(r Rule) {
	registry = append(registry, r)
}
