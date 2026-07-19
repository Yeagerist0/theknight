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

	tf := fmt.Sprintf(`resource "aws_s3_bucket_public_access_block" %q {
  bucket = %q

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
`, bucket, bucket)

	return Fix{
		Finding: f,
		Explanation: fmt.Sprintf(
			"Bucket %q has no Public Access Block configuration, so its ACL or bucket policy can grant public access. This resource blocks public ACLs and policies at the bucket level regardless of what the ACL or policy itself says.",
			bucket,
		),
		Terraform: tf,
	}, nil
}
