package rules

import (
	"testing"

	"github.com/Yeagerist0/theknight/pkg/scanner"
)

func TestEvaluate_SortsBySeverity(t *testing.T) {
	// Deliberately ordered High, Critical, High on input — Evaluate should
	// return Critical first, with the two High findings kept in their
	// original relative order (stable sort).
	resources := []scanner.Resource{
		{
			ID:   "sg-1",
			Type: "aws_security_group",
			Metadata: map[string]any{
				"group_name":         "ssh-open",
				"open_ingress_ports": []int32{22},
				"open_all_ports":     false,
			},
		},
		{
			ID:   "public-bucket",
			Type: "aws_s3_bucket",
			Metadata: map[string]any{
				"acl_public_read":             true,
				"public_access_block_enabled": false,
			},
		},
		{
			ID:   "arn:aws:iam::123456789012:role/deploy",
			Type: "aws_iam_role",
			Metadata: map[string]any{
				"role_name":                "deploy",
				"has_wildcard_action":      true,
				"action_wildcard_policies": []string{"AdminAccess"},
				"publicly_assumable":       false,
			},
		},
	}

	findings := Evaluate(resources)
	if len(findings) < 3 {
		t.Fatalf("Evaluate() returned %d findings, want at least 3 (sg-open-ingress, s3-public-read, iam-wildcard-action)", len(findings))
	}

	for i := 1; i < len(findings); i++ {
		if severityRank[findings[i].Severity] > severityRank[findings[i-1].Severity] {
			t.Errorf("findings not sorted most-severe-first: index %d (%s) outranks index %d (%s)",
				i, findings[i].Severity, i-1, findings[i-1].Severity)
		}
	}

	if findings[0].Severity != SeverityCritical {
		t.Errorf("findings[0].Severity = %v, want %v (s3-public-read is the only Critical finding here)", findings[0].Severity, SeverityCritical)
	}
	if findings[0].RuleID != "s3-public-read" {
		t.Errorf("findings[0].RuleID = %q, want %q", findings[0].RuleID, "s3-public-read")
	}

	// The two High findings (sg-open-ingress from sg-1, iam-wildcard-action
	// from deploy) should keep their original relative order: sg-1 was
	// discovered before deploy in the input.
	var highOrder []string
	for _, f := range findings {
		if f.Severity == SeverityHigh {
			highOrder = append(highOrder, f.RuleID)
		}
	}
	if len(highOrder) != 2 || highOrder[0] != "sg-open-ingress" || highOrder[1] != "iam-wildcard-action" {
		t.Errorf("High-severity findings order = %v, want [sg-open-ingress iam-wildcard-action] (stable sort should preserve input order)", highOrder)
	}
}

func TestParseSeverity(t *testing.T) {
	tests := []struct {
		input   string
		want    Severity
		wantErr bool
	}{
		{"low", SeverityLow, false},
		{"MEDIUM", SeverityMedium, false},
		{" High ", SeverityHigh, false},
		{"Critical", SeverityCritical, false},
		{"", "", true},
		{"catastrophic", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := ParseSeverity(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ParseSeverity(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("ParseSeverity(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestFilter(t *testing.T) {
	findings := []Finding{
		{RuleID: "low-finding", Severity: SeverityLow},
		{RuleID: "medium-finding", Severity: SeverityMedium},
		{RuleID: "high-finding", Severity: SeverityHigh},
		{RuleID: "critical-finding", Severity: SeverityCritical},
	}

	tests := []struct {
		min     Severity
		wantIDs []string
	}{
		{SeverityLow, []string{"low-finding", "medium-finding", "high-finding", "critical-finding"}},
		{SeverityHigh, []string{"high-finding", "critical-finding"}},
		{SeverityCritical, []string{"critical-finding"}},
	}

	for _, tt := range tests {
		t.Run(string(tt.min), func(t *testing.T) {
			got := Filter(findings, tt.min)
			if len(got) != len(tt.wantIDs) {
				t.Fatalf("Filter(min=%s) returned %d findings, want %d", tt.min, len(got), len(tt.wantIDs))
			}
			for i, f := range got {
				if f.RuleID != tt.wantIDs[i] {
					t.Errorf("Filter(min=%s)[%d].RuleID = %q, want %q", tt.min, i, f.RuleID, tt.wantIDs[i])
				}
			}
		})
	}
}

func TestFilter_UnknownMinReturnsUnchanged(t *testing.T) {
	findings := []Finding{{RuleID: "a", Severity: SeverityLow}}
	got := Filter(findings, Severity("not-a-real-severity"))
	if len(got) != 1 {
		t.Errorf("Filter() with an invalid min returned %d findings, want all findings unchanged", len(got))
	}
}

func TestFilter_UnknownFindingSeverityExcluded(t *testing.T) {
	findings := []Finding{{RuleID: "a", Severity: Severity("not-a-real-severity")}}
	got := Filter(findings, SeverityLow)
	if len(got) != 0 {
		t.Errorf("Filter() = %d findings, want 0 (a finding with an unrecognized severity shouldn't pass any threshold)", len(got))
	}
}
