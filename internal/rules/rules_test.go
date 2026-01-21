package rules

import "testing"

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
