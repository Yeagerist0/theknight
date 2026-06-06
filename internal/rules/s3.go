package rules

import (
	"fmt"

	"github.com/Yeagerist0/theknight/internal/scanner"
)

func init() {
	Register(s3PublicReadRule{})
}

type s3PublicReadRule struct{}

func (s3PublicReadRule) ID() string { return "s3-public-read" }

func (s3PublicReadRule) Applies(r scanner.Resource) bool {
	return r.Type == "aws_s3_bucket"
}

func (s3PublicReadRule) Evaluate(r scanner.Resource) (Finding, bool) {
	if blocked, _ := r.Metadata["public_access_block_enabled"].(bool); blocked {
		return Finding{}, false
	}

	aclPublic, _ := r.Metadata["acl_public_read"].(bool)
	policyPublic, _ := r.Metadata["policy_public"].(bool)
	if !aclPublic && !policyPublic {
		return Finding{}, false
	}

	via := "bucket policy"
	if aclPublic {
		via = "bucket ACL"
	}

	return Finding{
		RuleID:        "s3-public-read",
		Resource:      r,
		Severity:      SeverityCritical,
		Title:         "S3 bucket allows public read access",
		Description:   fmt.Sprintf("Bucket %q grants public read access via %s and has no Public Access Block configuration restricting it.", r.ID, via),
		RemediationID: "s3-block-public-access",
	}, true
}
