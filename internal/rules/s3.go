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

// A missing metadata key (the scanner couldn't collect that particular
// signal for this bucket — see internal/scanner/s3.go) type-asserts to
// Go's zero value, false, for every signal here. That default is
// conservative in the direction that matters for a security scanner: an
// unknown public_access_block_enabled reads as "not blocked", so a
// confirmed-public ACL still fires; an unknown acl_public_read reads as
// "not public via ACL", so it falls through to whatever the policy signal
// says instead of masking it. The failure mode this can't fully avoid is a
// false negative when every signal for a bucket is unknown at once — that
// case is still visible to the operator via the warning discoverS3
// surfaces, just not in the findings table.
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

func init() {
	Register(s3PublicWriteRule{})
}

type s3PublicWriteRule struct{}

func (s3PublicWriteRule) ID() string { return "s3-public-write" }

func (s3PublicWriteRule) Applies(r scanner.Resource) bool {
	return r.Type == "aws_s3_bucket"
}

// s3PublicWriteRule only fires off the ACL signal. GetBucketPolicyStatus
// reports whether a bucket is public at all, not which permission a public
// policy grants, so a policy-driven public-write can't be distinguished
// from policy-driven public-read with the data the scanner currently
// collects.
func (s3PublicWriteRule) Evaluate(r scanner.Resource) (Finding, bool) {
	if blocked, _ := r.Metadata["public_access_block_enabled"].(bool); blocked {
		return Finding{}, false
	}

	if aclPublic, _ := r.Metadata["acl_public_write"].(bool); !aclPublic {
		return Finding{}, false
	}

	return Finding{
		RuleID:        "s3-public-write",
		Resource:      r,
		Severity:      SeverityCritical,
		Title:         "S3 bucket allows public write access",
		Description:   fmt.Sprintf("Bucket %q grants public write access via its ACL and has no Public Access Block configuration restricting it. Anyone can upload or overwrite objects in this bucket.", r.ID),
		RemediationID: "s3-block-public-access",
	}, true
}
