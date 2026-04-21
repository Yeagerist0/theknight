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
