package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Yeagerist0/theknight/internal/rules"
	"github.com/Yeagerist0/theknight/internal/scanner"
)

func sampleFindings() []rules.Finding {
	return []rules.Finding{
		{
			RuleID:        "s3-public-read",
			Resource:      scanner.Resource{ID: "my-bucket", Type: "aws_s3_bucket"},
			Severity:      rules.SeverityCritical,
			Title:         "S3 bucket allows public read access",
			Description:   "Bucket is public.",
			RemediationID: "s3-block-public-access",
		},
		{
			RuleID:        "sg-open-ingress",
			Resource:      scanner.Resource{ID: "sg-123", Type: "aws_security_group"},
			Severity:      rules.SeverityHigh,
			Title:         "Security group open to the internet on a sensitive port",
			Description:   "Port 22 is open.",
			RemediationID: "sg-restrict-ingress-cidr",
		},
	}
}

func TestWrite_Table(t *testing.T) {
	var buf bytes.Buffer
	if err := Write(&buf, "table", sampleFindings()); err != nil {
		t.Fatalf("Write() error = %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "SEVERITY") || !strings.Contains(out, "RULE") {
		t.Errorf("table output missing header: %s", out)
	}
	if !strings.Contains(out, "s3-public-read") || !strings.Contains(out, "sg-open-ingress") {
		t.Errorf("table output missing expected rule IDs: %s", out)
	}
}

func TestWrite_TableEmpty(t *testing.T) {
	var buf bytes.Buffer
	if err := Write(&buf, "table", nil); err != nil {
		t.Fatalf("Write() error = %v", err)
	}

	if got := strings.TrimSpace(buf.String()); got != "no findings." {
		t.Errorf("Write() empty table output = %q, want %q", got, "no findings.")
	}
}

func TestWrite_TableNoColorForNonTerminalWriter(t *testing.T) {
	var buf bytes.Buffer
	if err := Write(&buf, "table", sampleFindings()); err != nil {
		t.Fatalf("Write() error = %v", err)
	}

	if strings.Contains(buf.String(), "\033[") {
		t.Errorf("table output written to a bytes.Buffer (not a terminal) contains ANSI escape codes:\n%s", buf.String())
	}
}

func TestWrite_DefaultFormatIsTable(t *testing.T) {
	var buf bytes.Buffer
	if err := Write(&buf, "", sampleFindings()); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	if !strings.Contains(buf.String(), "SEVERITY") {
		t.Errorf("empty format string should behave like \"table\", got: %s", buf.String())
	}
}

func TestWrite_JSON(t *testing.T) {
	var buf bytes.Buffer
	if err := Write(&buf, "json", sampleFindings()); err != nil {
		t.Fatalf("Write() error = %v", err)
	}

	var decoded []map[string]any
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, buf.String())
	}
	if len(decoded) != 2 {
		t.Fatalf("got %d findings in JSON output, want 2", len(decoded))
	}

	// Field names should be camelCase per proper JSON convention, not the
	// raw Go struct field names (RuleID, RemediationID, ...).
	first := decoded[0]
	for _, key := range []string{"ruleId", "resource", "severity", "title", "description", "remediationId"} {
		if _, ok := first[key]; !ok {
			t.Errorf("JSON finding missing expected key %q, got keys: %v", key, keysOf(first))
		}
	}

	resource, ok := first["resource"].(map[string]any)
	if !ok {
		t.Fatalf("resource field is not an object: %v", first["resource"])
	}
	for _, key := range []string{"id", "type", "region", "metadata"} {
		if _, ok := resource[key]; !ok {
			t.Errorf("JSON resource missing expected key %q, got keys: %v", key, keysOf(resource))
		}
	}
}

func TestWrite_JSONEmpty(t *testing.T) {
	var buf bytes.Buffer
	if err := Write(&buf, "json", nil); err != nil {
		t.Fatalf("Write() error = %v", err)
	}

	// A nil slice marshals to the JSON literal "null", which Go silently
	// unmarshals into a nil slice without error — so decoding and checking
	// len() == 0 wouldn't have caught this. A consumer doing `jq '.[]'` or
	// iterating the array in any other language breaks on "null"; check
	// the raw bytes to make sure Write() never emits it.
	if got := strings.TrimSpace(buf.String()); got != "[]" {
		t.Errorf("Write() empty JSON output = %q, want %q (a nil slice must not marshal to \"null\")", got, "[]")
	}

	var decoded []map[string]any
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, buf.String())
	}
	if len(decoded) != 0 {
		t.Errorf("got %d findings, want 0", len(decoded))
	}
}

func TestWrite_UnknownFormat(t *testing.T) {
	var buf bytes.Buffer
	err := Write(&buf, "yaml", sampleFindings())
	if err == nil {
		t.Fatal("Write() error = nil, want non-nil for an unsupported format")
	}
}

func TestColorize(t *testing.T) {
	tests := []struct {
		severity rules.Severity
		wantCode string
	}{
		{rules.SeverityCritical, ansiBoldRed},
		{rules.SeverityHigh, ansiRed},
		{rules.SeverityMedium, ansiYellow},
		{rules.SeverityLow, ansiCyan},
	}

	for _, tt := range tests {
		got := colorize(tt.severity, "high")
		if !strings.HasPrefix(got, tt.wantCode) || !strings.HasSuffix(got, ansiReset) {
			t.Errorf("colorize(%v, ...) = %q, want wrapped in %q...%q", tt.severity, got, tt.wantCode, ansiReset)
		}
	}
}

func TestColorize_UnknownSeverityReturnsTextUnchanged(t *testing.T) {
	got := colorize(rules.Severity("made-up"), "made-up")
	if got != "made-up" {
		t.Errorf("colorize() for an unrecognized severity = %q, want unchanged text", got)
	}
}

func keysOf(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}
