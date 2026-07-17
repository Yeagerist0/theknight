// Package rules evaluates scanned resources against misconfiguration
// patterns (public S3 buckets, over-permissioned IAM roles, open security
// groups, ...) and produces prioritized Findings.
package rules

import (
	"fmt"
	"sort"
	"strings"

	"github.com/Yeagerist0/theknight/internal/scanner"
)

type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
)

// severityRank orders severities low-to-high for threshold comparisons.
// Higher rank means more severe.
var severityRank = map[Severity]int{
	SeverityLow:      0,
	SeverityMedium:   1,
	SeverityHigh:     2,
	SeverityCritical: 3,
}

// ParseSeverity parses a case-insensitive severity name (as a user would
// type it on the CLI) into a Severity, rejecting anything not in
// severityRank.
func ParseSeverity(s string) (Severity, error) {
	sev := Severity(strings.ToLower(strings.TrimSpace(s)))
	if _, ok := severityRank[sev]; !ok {
		return "", fmt.Errorf("unknown severity %q (want one of: low, medium, high, critical)", s)
	}
	return sev, nil
}

// Finding is a single detected misconfiguration, tied back to the resource
// it was found on and (eventually) a remediation template ID.
type Finding struct {
	RuleID        string           `json:"ruleId"`
	Resource      scanner.Resource `json:"resource"`
	Severity      Severity         `json:"severity"`
	Title         string           `json:"title"`
	Description   string           `json:"description"`
	RemediationID string           `json:"remediationId"`
}

// Rule inspects a single resource and returns a Finding if it matches.
type Rule interface {
	ID() string
	Applies(r scanner.Resource) bool
	Evaluate(r scanner.Resource) (Finding, bool)
}

// Evaluate runs every registered rule against every resource, returning
// findings ordered most-severe first. The sort is stable, so findings of
// equal severity keep their original resource/rule discovery order rather
// than shuffling arbitrarily on every run.
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

	sort.SliceStable(findings, func(i, j int) bool {
		return severityRank[findings[i].Severity] > severityRank[findings[j].Severity]
	})

	return findings
}

// Filter returns the findings whose Severity is at or above min. An
// unrecognized Severity on a Finding (shouldn't happen with rules defined
// in this package, but Finding.Severity isn't a closed type) is treated
// as below every threshold, so it's excluded rather than risking a panic
// or silently ranking above Critical.
func Filter(findings []Finding, min Severity) []Finding {
	minRank, ok := severityRank[min]
	if !ok {
		return findings
	}

	var filtered []Finding
	for _, f := range findings {
		if rank, ok := severityRank[f.Severity]; ok && rank >= minRank {
			filtered = append(filtered, f)
		}
	}
	return filtered
}

var registry []Rule

// Register adds a rule to the default registry. Rule implementations call
// this from an init() in their own file, so adding a new check never
// requires touching this package.
func Register(r Rule) {
	registry = append(registry, r)
}
