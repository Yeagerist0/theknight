package scanner

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
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

func TestDiscoverS3_PublicViaACL(t *testing.T) {
	fake := &fakeS3{
		buckets: []types.Bucket{{Name: aws.String("public-bucket")}},
		grants: map[string][]types.Grant{
			"public-bucket": {
				{Grantee: &types.Grantee{URI: aws.String(granteeAllUsers)}, Permission: types.PermissionRead},
			},
		},
	}

	resources, err := discoverS3(context.Background(), fake)
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

func TestDiscoverS3_PrivateBucket(t *testing.T) {
	fake := &fakeS3{
		buckets:      []types.Bucket{{Name: aws.String("private-bucket")}},
		policyPublic: map[string]bool{"private-bucket": false},
		blockEnabled: map[string]bool{"private-bucket": true},
	}

	resources, err := discoverS3(context.Background(), fake)
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

	resources, err := discoverS3(context.Background(), fake)
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

	resources, err := discoverS3(context.Background(), fake)
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

	resources, err := discoverS3(context.Background(), fake)
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

	resources, err := discoverS3(context.Background(), fake)
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

	resources, err := discoverS3(context.Background(), fake)
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
