package remediate

import (
	"fmt"

	"github.com/Yeagerist0/theknight/pkg/rules"
)

func init() {
	register("s3-block-public-access", s3BlockPublicAccess)
}

func s3BlockPublicAccess(f rules.Finding) (Fix, error) {
	bucket := f.Resource.ID
	// S3 bucket names allow dots (common for virtual-hosted-style buckets
	// like "assets.example.com") and may start with a digit -- neither
	// valid in a Terraform resource label, which Terraform restricts to
	// [a-zA-Z_][a-zA-Z0-9_-]* even though HCL's block-header grammar quotes
	// it like any other string. Used unescaped as the label, a bucket name
	// like that renders Terraform `terraform validate` rejects outright:
	// a remediation PR that can't even be planned. SafeIdent is exactly
	// this codebase's existing fix for that (see its doc comment and
	// pkg/remediate/iam.go, pkg/remediate/ec2.go, which already use it)
	// -- only the label needs it; `bucket = %q` below is a quoted string
	// value, not an identifier, so the real bucket name is still correct
	// there regardless of what characters it contains.
	ident := SafeIdent(bucket)

	tf := fmt.Sprintf(`resource "aws_s3_bucket_public_access_block" %q {
  bucket = %q

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
`, ident, bucket)

	return Fix{
		Finding: f,
		Explanation: fmt.Sprintf(
			"Bucket %q has no Public Access Block configuration, so its ACL or bucket policy can grant public access. This resource blocks public ACLs and policies at the bucket level regardless of what the ACL or policy itself says.",
			bucket,
		),
		Terraform: tf,
	}, nil
}
