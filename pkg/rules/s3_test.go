package rules

import (
	"testing"

	"github.com/Yeagerist0/theknight/pkg/scanner"
)

func TestS3PublicReadRule_Applies(t *testing.T) {
	rule := s3PublicReadRule{}

	if !rule.Applies(scanner.Resource{Type: "aws_s3_bucket"}) {
		t.Error("expected rule to apply to aws_s3_bucket")
	}
	if rule.Applies(scanner.Resource{Type: "aws_iam_role"}) {
		t.Error("expected rule not to apply to aws_iam_role")
	}
}

func TestS3PublicReadRule_Evaluate(t *testing.T) {
	rule := s3PublicReadRule{}

	tests := []struct {
		name     string
		metadata map[string]any
		want     bool
	}{
		{
			name: "public via ACL",
			metadata: map[string]any{
				"acl_public_read":             true,
				"policy_public_read":          false,
				"public_access_block_enabled": false,
			},
			want: true,
		},
		{
			name: "public via bucket policy",
			metadata: map[string]any{
				"acl_public_read":             false,
				"policy_public_read":          true,
				"public_access_block_enabled": false,
			},
			want: true,
		},
		{
			name: "public but blocked by public access block",
			metadata: map[string]any{
				"acl_public_read":             true,
				"policy_public_read":          true,
				"public_access_block_enabled": true,
			},
			want: false,
		},
		{
			name: "private bucket",
			metadata: map[string]any{
				"acl_public_read":             false,
				"policy_public_read":          false,
				"public_access_block_enabled": false,
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := scanner.Resource{ID: "test-bucket", Type: "aws_s3_bucket", Metadata: tt.metadata}
			finding, got := rule.Evaluate(r)
			if got != tt.want {
				t.Fatalf("Evaluate() matched = %v, want %v", got, tt.want)
			}
			if got && finding.RuleID != "s3-public-read" {
				t.Errorf("Finding.RuleID = %q, want %q", finding.RuleID, "s3-public-read")
			}
		})
	}
}

func TestS3PublicWriteRule_Applies(t *testing.T) {
	rule := s3PublicWriteRule{}

	if !rule.Applies(scanner.Resource{Type: "aws_s3_bucket"}) {
		t.Error("expected rule to apply to aws_s3_bucket")
	}
	if rule.Applies(scanner.Resource{Type: "aws_iam_role"}) {
		t.Error("expected rule not to apply to aws_iam_role")
	}
}

func TestS3PublicWriteRule_Evaluate(t *testing.T) {
	rule := s3PublicWriteRule{}

	tests := []struct {
		name     string
		metadata map[string]any
		want     bool
	}{
		{
			name: "public write via ACL",
			metadata: map[string]any{
				"acl_public_write":            true,
				"public_access_block_enabled": false,
			},
			want: true,
		},
		{
			name: "public write blocked by public access block",
			metadata: map[string]any{
				"acl_public_write":            true,
				"public_access_block_enabled": true,
			},
			want: false,
		},
		{
			name: "read-only bucket",
			metadata: map[string]any{
				"acl_public_write":            false,
				"public_access_block_enabled": false,
			},
			want: false,
		},
		{
			name: "public write via policy",
			metadata: map[string]any{
				"acl_public_write":            false,
				"policy_public_write":         true,
				"public_access_block_enabled": false,
			},
			want: true,
		},
		{
			name: "public read via policy does not imply write",
			metadata: map[string]any{
				"acl_public_write":            false,
				"policy_public_read":          true,
				"policy_public_write":         false,
				"public_access_block_enabled": false,
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := scanner.Resource{ID: "test-bucket", Type: "aws_s3_bucket", Metadata: tt.metadata}
			finding, got := rule.Evaluate(r)
			if got != tt.want {
				t.Fatalf("Evaluate() matched = %v, want %v", got, tt.want)
			}
			if got && finding.RuleID != "s3-public-write" {
				t.Errorf("Finding.RuleID = %q, want %q", finding.RuleID, "s3-public-write")
			}
		})
	}
}
