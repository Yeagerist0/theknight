package remediate

import (
	"strings"
	"testing"

	"github.com/Yeagerist0/theknight/pkg/rules"
	"github.com/Yeagerist0/theknight/pkg/scanner"
)

func TestS3BlockPublicAccess(t *testing.T) {
	f := rules.Finding{
		RuleID:        "s3-public-read",
		RemediationID: "s3-block-public-access",
		Resource:      scanner.Resource{ID: "my-app-uploads", Type: "aws_s3_bucket"},
	}

	fix, ok, err := Generate(f)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}
	if !ok {
		t.Fatal("Generate() ok = false, want true")
	}

	if !strings.Contains(fix.Terraform, `resource "aws_s3_bucket_public_access_block" "my-app-uploads"`) {
		t.Errorf("Terraform missing expected resource block:\n%s", fix.Terraform)
	}
	if !strings.Contains(fix.Terraform, "block_public_acls       = true") {
		t.Errorf("Terraform missing block_public_acls:\n%s", fix.Terraform)
	}
	if !strings.Contains(fix.Explanation, "my-app-uploads") {
		t.Errorf("Explanation missing bucket name: %s", fix.Explanation)
	}
}

// TestS3BlockPublicAccess_DottedBucketNameGetsSafeIdent is the regression
// test for the gap this fix closes: S3 bucket names allow dots (common for
// virtual-hosted-style names like "assets.example.com") and may start with
// a digit, neither valid in a Terraform resource label even though HCL's
// grammar quotes it like any other string -- Terraform itself restricts a
// resource label to [a-zA-Z_][a-zA-Z0-9_-]*. Used raw as the label, this
// bucket name would render Terraform that fails `terraform validate`,
// while the `bucket = "..."` attribute value is unaffected since that's a
// quoted string, not an identifier.
func TestS3BlockPublicAccess_DottedBucketNameGetsSafeIdent(t *testing.T) {
	bucket := "assets.example.com"
	f := rules.Finding{
		RuleID:        "s3-public-read",
		RemediationID: "s3-block-public-access",
		Resource:      scanner.Resource{ID: bucket, Type: "aws_s3_bucket"},
	}

	fix, ok, err := Generate(f)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}
	if !ok {
		t.Fatal("Generate() ok = false, want true")
	}

	wantLabel := SafeIdent(bucket)
	if !strings.Contains(fix.Terraform, `resource "aws_s3_bucket_public_access_block" "`+wantLabel+`"`) {
		t.Errorf("Terraform resource label = want SafeIdent(%q) = %q, got:\n%s", bucket, wantLabel, fix.Terraform)
	}
	if strings.Contains(fix.Terraform, `resource "aws_s3_bucket_public_access_block" "`+bucket+`"`) {
		t.Errorf("Terraform uses the raw bucket name as the resource label -- invalid Terraform identifier (contains dots):\n%s", fix.Terraform)
	}
	// The attribute VALUE is a quoted string, not an identifier -- the real
	// bucket name (dots and all) must still appear there unchanged.
	if !strings.Contains(fix.Terraform, `bucket = "`+bucket+`"`) {
		t.Errorf("Terraform bucket attribute should still carry the real bucket name:\n%s", fix.Terraform)
	}
}
