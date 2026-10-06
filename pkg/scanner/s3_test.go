package scanner

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/aws-sdk-go-v2/service/s3control"
	s3controltypes "github.com/aws/aws-sdk-go-v2/service/s3control/types"
	smithy "github.com/aws/smithy-go"
)

// fakeAPIError satisfies smithy.APIError so tests can simulate the
// "not configured" responses S3 returns for buckets with no policy or no
// public access block, without a real AWS error type.
type fakeAPIError struct{ code string }

func (e fakeAPIError) Error() string                 { return e.code }
func (e fakeAPIError) ErrorCode() string             { return e.code }
func (e fakeAPIError) ErrorMessage() string          { return e.code }
func (e fakeAPIError) ErrorFault() smithy.ErrorFault { return smithy.FaultUnknown }

type fakeS3 struct {
	buckets      []types.Bucket
	grants       map[string][]types.Grant
	policyPublic map[string]bool
	policyDocs   map[string]string
	blockEnabled map[string]bool
	aclErr       error
	policyErr    error
	policyDocErr error
	blockErr     error
}

func (f *fakeS3) ListBuckets(ctx context.Context, params *s3.ListBucketsInput, optFns ...func(*s3.Options)) (*s3.ListBucketsOutput, error) {
	return &s3.ListBucketsOutput{Buckets: f.buckets}, nil
}

func (f *fakeS3) GetBucketAcl(ctx context.Context, params *s3.GetBucketAclInput, optFns ...func(*s3.Options)) (*s3.GetBucketAclOutput, error) {
	if f.aclErr != nil {
		return nil, f.aclErr
	}
	return &s3.GetBucketAclOutput{Grants: f.grants[aws.ToString(params.Bucket)]}, nil
}

func (f *fakeS3) GetBucketPolicyStatus(ctx context.Context, params *s3.GetBucketPolicyStatusInput, optFns ...func(*s3.Options)) (*s3.GetBucketPolicyStatusOutput, error) {
	if f.policyErr != nil {
		return nil, f.policyErr
	}
	public, ok := f.policyPublic[aws.ToString(params.Bucket)]
	if !ok {
		return nil, fakeAPIError{code: "NoSuchBucketPolicy"}
	}
	return &s3.GetBucketPolicyStatusOutput{PolicyStatus: &types.PolicyStatus{IsPublic: aws.Bool(public)}}, nil
}

func (f *fakeS3) GetBucketPolicy(ctx context.Context, params *s3.GetBucketPolicyInput, optFns ...func(*s3.Options)) (*s3.GetBucketPolicyOutput, error) {
	if f.policyDocErr != nil {
		return nil, f.policyDocErr
	}
	doc, ok := f.policyDocs[aws.ToString(params.Bucket)]
	if !ok {
		return nil, fakeAPIError{code: "NoSuchBucketPolicy"}
	}
	return &s3.GetBucketPolicyOutput{Policy: aws.String(doc)}, nil
}

func (f *fakeS3) GetPublicAccessBlock(ctx context.Context, params *s3.GetPublicAccessBlockInput, optFns ...func(*s3.Options)) (*s3.GetPublicAccessBlockOutput, error) {
	if f.blockErr != nil {
		return nil, f.blockErr
	}
	enabled, ok := f.blockEnabled[aws.ToString(params.Bucket)]
	if !ok {
		return nil, fakeAPIError{code: "NoSuchPublicAccessBlockConfiguration"}
	}
	return &s3.GetPublicAccessBlockOutput{PublicAccessBlockConfiguration: &types.PublicAccessBlockConfiguration{
		BlockPublicAcls:       aws.Bool(enabled),
		BlockPublicPolicy:     aws.Bool(enabled),
		IgnorePublicAcls:      aws.Bool(enabled),
		RestrictPublicBuckets: aws.Bool(enabled),
	}}, nil
}

// fakeS3Control simulates the account-level Block Public Access API.
// blockEnabled nil means "no account-level config" (NoSuchPublicAccessBlockConfiguration),
// matching an account that never set one -- the common case this fake
// defaults to so existing tests, which only care about bucket-level
// behavior, don't need to know this API exists.
type fakeS3Control struct {
	blockEnabled *bool // nil = not configured
	err          error
}

func (f *fakeS3Control) GetPublicAccessBlock(ctx context.Context, params *s3control.GetPublicAccessBlockInput, optFns ...func(*s3control.Options)) (*s3control.GetPublicAccessBlockOutput, error) {
	if f.err != nil {
		return nil, f.err
	}
	if f.blockEnabled == nil {
		return nil, fakeAPIError{code: "NoSuchPublicAccessBlockConfiguration"}
	}
	enabled := *f.blockEnabled
	return &s3control.GetPublicAccessBlockOutput{PublicAccessBlockConfiguration: &s3controltypes.PublicAccessBlockConfiguration{
		BlockPublicAcls:       aws.Bool(enabled),
		BlockPublicPolicy:     aws.Bool(enabled),
		IgnorePublicAcls:      aws.Bool(enabled),
		RestrictPublicBuckets: aws.Bool(enabled),
	}}, nil
}

func TestDiscoverS3_PublicViaACL(t *testing.T) {
	fake := &fakeS3{
		buckets: []types.Bucket{{Name: aws.String("public-bucket")}},
		grants: map[string][]types.Grant{
			"public-bucket": {
				{Grantee: &types.Grantee{URI: aws.String(granteeAllUsers)}, Permission: types.PermissionRead},
			},
		},
	}

	resources, err := discoverS3(context.Background(), fake, &fakeS3Control{}, "")
	if err != nil {
		t.Fatalf("discoverS3() error = %v", err)
	}
	if len(resources) != 1 {
		t.Fatalf("got %d resources, want 1", len(resources))
	}

	r := resources[0]
	if got := r.Metadata["acl_public_read"]; got != true {
		t.Errorf("acl_public_read = %v, want true", got)
	}
	if got := r.Metadata["policy_public"]; got != false {
		t.Errorf("policy_public = %v, want false (no policy configured)", got)
	}
	if got := r.Metadata["public_access_block_enabled"]; got != false {
		t.Errorf("public_access_block_enabled = %v, want false (not configured)", got)
	}
}

// TestDiscoverS3_AccountLevelBlockSuppressesBucketACL is the regression test
// for the bug this fix closes: a bucket with no bucket-level Block Public
// Access configuration of its own, but a public ACL, sitting under an
// account that has account-level Block Public Access fully enabled. AWS
// enforces the union of the two, so this bucket's ACL grant is inert — the
// scanner must not report it as a live public-read finding.
func TestDiscoverS3_AccountLevelBlockSuppressesBucketACL(t *testing.T) {
	fake := &fakeS3{
		buckets: []types.Bucket{{Name: aws.String("bucket-under-account-block")}},
		grants: map[string][]types.Grant{
			"bucket-under-account-block": {
				{Grantee: &types.Grantee{URI: aws.String(granteeAllUsers)}, Permission: types.PermissionRead},
			},
		},
		// No entry in blockEnabled: this bucket has no PAB config of its own.
	}
	enabled := true
	fakeControl := &fakeS3Control{blockEnabled: &enabled}

	resources, err := discoverS3(context.Background(), fake, fakeControl, "111111111111")
	if err != nil {
		t.Fatalf("discoverS3() error = %v", err)
	}
	r := resources[0]
	if got := r.Metadata["acl_public_read"]; got != true {
		t.Errorf("acl_public_read = %v, want true (the ACL itself is still public)", got)
	}
	if got := r.Metadata["public_access_block_enabled"]; got != true {
		t.Errorf("public_access_block_enabled = %v, want true (account-level block covers this bucket)", got)
	}
}

// TestDiscoverS3_PartialAccountBlockDoesNotSuppress checks the merge is
// per-dimension, not "either source fully blocks": an account missing even
// one of the four Block Public Access flags must not suppress a bucket that
// has none of its own -- AWS requires all four, from either source, before
// public access is actually inert.
func TestDiscoverS3_PartialAccountBlockDoesNotSuppress(t *testing.T) {
	fake := &fakeS3{
		buckets: []types.Bucket{{Name: aws.String("bucket-under-partial-block")}},
		grants: map[string][]types.Grant{
			"bucket-under-partial-block": {
				{Grantee: &types.Grantee{URI: aws.String(granteeAllUsers)}, Permission: types.PermissionRead},
			},
		},
	}
	fakeControl := &fakeS3Control{} // not configured at all -> every dimension false

	resources, err := discoverS3(context.Background(), fake, fakeControl, "111111111111")
	if err != nil {
		t.Fatalf("discoverS3() error = %v", err)
	}
	r := resources[0]
	if got := r.Metadata["public_access_block_enabled"]; got != false {
		t.Errorf("public_access_block_enabled = %v, want false (account has no PAB config either)", got)
	}
}

func TestDiscoverS3_PrivateBucket(t *testing.T) {
	fake := &fakeS3{
		buckets:      []types.Bucket{{Name: aws.String("private-bucket")}},
		policyPublic: map[string]bool{"private-bucket": false},
		blockEnabled: map[string]bool{"private-bucket": true},
	}

	resources, err := discoverS3(context.Background(), fake, &fakeS3Control{}, "")
	if err != nil {
		t.Fatalf("discoverS3() error = %v", err)
	}
	if len(resources) != 1 {
		t.Fatalf("got %d resources, want 1", len(resources))
	}

	r := resources[0]
	if got := r.Metadata["acl_public_read"]; got != false {
		t.Errorf("acl_public_read = %v, want false", got)
	}
	if got := r.Metadata["public_access_block_enabled"]; got != true {
		t.Errorf("public_access_block_enabled = %v, want true", got)
	}
}

func TestDiscoverS3_PolicyGrantsReadOnly(t *testing.T) {
	fake := &fakeS3{
		buckets:      []types.Bucket{{Name: aws.String("read-only-policy-bucket")}},
		policyPublic: map[string]bool{"read-only-policy-bucket": true},
		policyDocs: map[string]string{
			"read-only-policy-bucket": `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::read-only-policy-bucket/*"}]}`,
		},
		blockEnabled: map[string]bool{"read-only-policy-bucket": false},
	}

	resources, err := discoverS3(context.Background(), fake, &fakeS3Control{}, "")
	if err != nil {
		t.Fatalf("discoverS3() error = %v", err)
	}

	r := resources[0]
	if got := r.Metadata["policy_public_read"]; got != true {
		t.Errorf("policy_public_read = %v, want true", got)
	}
	if got := r.Metadata["policy_public_write"]; got != false {
		t.Errorf("policy_public_write = %v, want false — the policy only grants s3:GetObject", got)
	}
}

func TestDiscoverS3_PolicyGrantsWriteOnly(t *testing.T) {
	fake := &fakeS3{
		buckets:      []types.Bucket{{Name: aws.String("write-only-policy-bucket")}},
		policyPublic: map[string]bool{"write-only-policy-bucket": true},
		policyDocs: map[string]string{
			"write-only-policy-bucket": `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"s3:PutObject","Resource":"arn:aws:s3:::write-only-policy-bucket/*"}]}`,
		},
		blockEnabled: map[string]bool{"write-only-policy-bucket": false},
	}

	resources, err := discoverS3(context.Background(), fake, &fakeS3Control{}, "")
	if err != nil {
		t.Fatalf("discoverS3() error = %v", err)
	}

	r := resources[0]
	if got := r.Metadata["policy_public_read"]; got != false {
		t.Errorf("policy_public_read = %v, want false — positive parsing evidence overrides the generic policy_public default", got)
	}
	if got := r.Metadata["policy_public_write"]; got != true {
		t.Errorf("policy_public_write = %v, want true", got)
	}
}

func TestDiscoverS3_PolicyGrantsFullAccess(t *testing.T) {
	fake := &fakeS3{
		buckets:      []types.Bucket{{Name: aws.String("full-access-policy-bucket")}},
		policyPublic: map[string]bool{"full-access-policy-bucket": true},
		policyDocs: map[string]string{
			"full-access-policy-bucket": `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:*","Resource":"arn:aws:s3:::full-access-policy-bucket/*"}]}`,
		},
		blockEnabled: map[string]bool{"full-access-policy-bucket": false},
	}

	resources, err := discoverS3(context.Background(), fake, &fakeS3Control{}, "")
	if err != nil {
		t.Fatalf("discoverS3() error = %v", err)
	}

	r := resources[0]
	if got := r.Metadata["policy_public_read"]; got != true {
		t.Errorf("policy_public_read = %v, want true", got)
	}
	if got := r.Metadata["policy_public_write"]; got != true {
		t.Errorf("policy_public_write = %v, want true", got)
	}
}

func TestDiscoverS3_PolicyDocumentUnreadableFallsBackConservatively(t *testing.T) {
	fake := &fakeS3{
		buckets:      []types.Bucket{{Name: aws.String("unreadable-policy-bucket")}},
		policyPublic: map[string]bool{"unreadable-policy-bucket": true},
		policyDocErr: errors.New("access denied"), // GetBucketPolicyStatus succeeded but GetBucketPolicy failed
		blockEnabled: map[string]bool{"unreadable-policy-bucket": false},
	}

	resources, err := discoverS3(context.Background(), fake, &fakeS3Control{}, "")
	if err == nil {
		t.Fatal("discoverS3() error = nil, want non-nil (the policy document call failed)")
	}

	r := resources[0]
	if got := r.Metadata["policy_public_read"]; got != true {
		t.Errorf("policy_public_read = %v, want true (falls back to policy_public when parsing isn't possible)", got)
	}
	if got := r.Metadata["policy_public_write"]; got != false {
		t.Errorf("policy_public_write = %v, want false (never assumed without positive evidence)", got)
	}
}

func TestDiscoverS3_PartialFailureStillReportsBucket(t *testing.T) {
	fake := &fakeS3{
		buckets:      []types.Bucket{{Name: aws.String("broken-bucket")}},
		aclErr:       errors.New("access denied"),
		policyPublic: map[string]bool{"broken-bucket": false},
		blockEnabled: map[string]bool{"broken-bucket": true},
	}

	resources, err := discoverS3(context.Background(), fake, &fakeS3Control{}, "")
	if err == nil {
		t.Fatal("discoverS3() error = nil, want non-nil (the ACL call failed)")
	}
	if len(resources) != 1 {
		t.Fatalf("got %d resources, want 1 — a failure on one signal (ACL) shouldn't drop the whole bucket", len(resources))
	}

	r := resources[0]
	if _, ok := r.Metadata["acl_public_read"]; ok {
		t.Errorf("acl_public_read should be absent when the ACL call failed, got %v", r.Metadata["acl_public_read"])
	}
	if got := r.Metadata["public_access_block_enabled"]; got != true {
		t.Errorf("public_access_block_enabled = %v, want true (that call succeeded independently of the ACL failure)", got)
	}
}
