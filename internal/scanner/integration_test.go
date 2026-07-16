//go:build integration

// Integration tests run the real discovery functions against LocalStack
// instead of the hand-rolled fakes used elsewhere in this package. The
// unit tests (fakes) prove the detection logic — the mapping from an AWS
// API response to Resource.Metadata — is correct in isolation. These tests
// prove the AWS SDK request/response wiring itself is correct: field
// names, pagination, decoding of what LocalStack's emulated APIs actually
// return, as opposed to what we assume they return in a fake.
//
// They deliberately do NOT chain into rules.Evaluate or remediate.Generate
// — importing internal/rules from here would create an import cycle
// (rules already imports scanner for scanner.Resource), and rules/remediate
// are pure functions over Resource/Finding structs that don't touch AWS at
// all, so real vs. fake Resource values exercise them identically. That
// coverage already exists in internal/rules and internal/remediate's own
// unit tests.
//
// Run with `make integration-test` (starts LocalStack, runs this file,
// tears it down) or manually against a running LocalStack instance with
// `go test -tags=integration ./internal/scanner/... -v`.
package scanner

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
)

const localstackEndpoint = "http://localhost:4566"

// localstackAWSConfig builds an aws.Config pointed at LocalStack with
// throwaway static credentials — LocalStack doesn't validate them, but the
// SDK still requires something non-empty to sign requests with.
func localstackAWSConfig() aws.Config {
	return aws.Config{
		Region:       "us-east-1",
		Credentials:  credentials.NewStaticCredentialsProvider("test", "test", ""),
		BaseEndpoint: aws.String(localstackEndpoint),
	}
}

func testID(prefix string) string {
	return fmt.Sprintf("%s-%d", prefix, time.Now().UnixNano())
}

func TestIntegration_DiscoverS3_PublicReadBucket(t *testing.T) {
	ctx := context.Background()
	client := s3.NewFromConfig(localstackAWSConfig(), func(o *s3.Options) {
		o.UsePathStyle = true // required to hit LocalStack directly on localhost:4566
	})

	bucket := testID("theknight-public-read")
	if _, err := client.CreateBucket(ctx, &s3.CreateBucketInput{
		Bucket: &bucket,
		ACL:    s3types.BucketCannedACLPublicRead,
	}); err != nil {
		t.Fatalf("CreateBucket: %v", err)
	}
	t.Cleanup(func() {
		client.DeleteBucket(ctx, &s3.DeleteBucketInput{Bucket: &bucket})
	})

	// AWS enables S3 Block Public Access by default on every new bucket
	// (since April 2023) — a public ACL alone no longer makes a bucket
	// reachable unless that default protection is explicitly turned off
	// first. This mirrors the real misconfiguration s3-public-read
	// targets: someone deliberately disabling the default, not a bucket
	// that was simply never touched.
	disable := false
	if _, err := client.PutPublicAccessBlock(ctx, &s3.PutPublicAccessBlockInput{
		Bucket: &bucket,
		PublicAccessBlockConfiguration: &s3types.PublicAccessBlockConfiguration{
			BlockPublicAcls:       &disable,
			BlockPublicPolicy:     &disable,
			IgnorePublicAcls:      &disable,
			RestrictPublicBuckets: &disable,
		},
	}); err != nil {
		t.Fatalf("PutPublicAccessBlock: %v", err)
	}

	resources, err := discoverS3(ctx, client)
	requireOnlyKnownLocalStackGap(t, err, bucket)

	resource := findResourceByID(t, resources, bucket)
	if got := resource.Metadata["acl_public_read"]; got != true {
		t.Errorf("acl_public_read = %v, want true (bucket created with public-read canned ACL)", got)
	}
	if got := resource.Metadata["acl_public_write"]; got != false {
		t.Errorf("acl_public_write = %v, want false (public-read ACL doesn't grant write)", got)
	}
	if got := resource.Metadata["public_access_block_enabled"]; got != false {
		t.Errorf("public_access_block_enabled = %v, want false (explicitly disabled above)", got)
	}
}

func TestIntegration_DiscoverS3_PrivateBucketWithPublicAccessBlock(t *testing.T) {
	ctx := context.Background()
	client := s3.NewFromConfig(localstackAWSConfig(), func(o *s3.Options) {
		o.UsePathStyle = true
	})

	bucket := testID("theknight-private")
	if _, err := client.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: &bucket}); err != nil {
		t.Fatalf("CreateBucket: %v", err)
	}
	t.Cleanup(func() {
		client.DeleteBucket(ctx, &s3.DeleteBucketInput{Bucket: &bucket})
	})

	blockAll := true
	if _, err := client.PutPublicAccessBlock(ctx, &s3.PutPublicAccessBlockInput{
		Bucket: &bucket,
		PublicAccessBlockConfiguration: &s3types.PublicAccessBlockConfiguration{
			BlockPublicAcls:       &blockAll,
			BlockPublicPolicy:     &blockAll,
			IgnorePublicAcls:      &blockAll,
			RestrictPublicBuckets: &blockAll,
		},
	}); err != nil {
		t.Fatalf("PutPublicAccessBlock: %v", err)
	}

	resources, err := discoverS3(ctx, client)
	requireOnlyKnownLocalStackGap(t, err, bucket)

	resource := findResourceByID(t, resources, bucket)
	if got := resource.Metadata["public_access_block_enabled"]; got != true {
		t.Errorf("public_access_block_enabled = %v, want true", got)
	}
	if got := resource.Metadata["acl_public_read"]; got != false {
		t.Errorf("acl_public_read = %v, want false (default private ACL)", got)
	}
}

func TestIntegration_DiscoverIAM_WildcardRole(t *testing.T) {
	ctx := context.Background()
	client := iam.NewFromConfig(localstackAWSConfig())

	roleName := testID("theknight-wildcard-role")
	trustPolicy := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}`

	if _, err := client.CreateRole(ctx, &iam.CreateRoleInput{
		RoleName:                 &roleName,
		AssumeRolePolicyDocument: &trustPolicy,
	}); err != nil {
		t.Fatalf("CreateRole: %v", err)
	}

	policyName := "AllowEverything"
	t.Cleanup(func() {
		client.DeleteRolePolicy(ctx, &iam.DeleteRolePolicyInput{RoleName: &roleName, PolicyName: &policyName})
		client.DeleteRole(ctx, &iam.DeleteRoleInput{RoleName: &roleName})
	})

	// A single statement with both Action: "*" and Resource: "*", exercising
	// the single-object (non-array) Statement parsing path against a real
	// IAM response — the array path is covered by the array trust policy
	// document IAM itself returns for AssumeRolePolicyDocument elsewhere.
	inlineDoc := `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"*","Resource":"*"}}`
	if _, err := client.PutRolePolicy(ctx, &iam.PutRolePolicyInput{
		RoleName:       &roleName,
		PolicyName:     &policyName,
		PolicyDocument: &inlineDoc,
	}); err != nil {
		t.Fatalf("PutRolePolicy: %v", err)
	}

	resources, err := discoverIAM(ctx, client)
	if err != nil {
		t.Fatalf("discoverIAM() error = %v", err)
	}

	var resource Resource
	found := false
	for _, r := range resources {
		if name, _ := r.Metadata["role_name"].(string); name == roleName {
			resource = r
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("role %s not found among %d discovered roles", roleName, len(resources))
	}

	if got := resource.Metadata["has_wildcard_action"]; got != true {
		t.Errorf("has_wildcard_action = %v, want true", got)
	}
	if got := resource.Metadata["has_wildcard_resource"]; got != true {
		t.Errorf("has_wildcard_resource = %v, want true", got)
	}

	actionPolicies, _ := resource.Metadata["action_wildcard_policies"].([]string)
	if len(actionPolicies) != 1 || actionPolicies[0] != policyName {
		t.Errorf("action_wildcard_policies = %v, want [%s]", actionPolicies, policyName)
	}
	resourcePolicies, _ := resource.Metadata["resource_wildcard_policies"].([]string)
	if len(resourcePolicies) != 1 || resourcePolicies[0] != policyName {
		t.Errorf("resource_wildcard_policies = %v, want [%s]", resourcePolicies, policyName)
	}

	// This role's trust policy only allows the ec2.amazonaws.com service
	// principal to assume it — an internal-only wildcard role, not a
	// publicly assumable one.
	if got := resource.Metadata["publicly_assumable"]; got != false {
		t.Errorf("publicly_assumable = %v, want false (service-principal-only trust policy)", got)
	}
}

func TestIntegration_DiscoverIAM_PubliclyAssumableRole(t *testing.T) {
	ctx := context.Background()
	client := iam.NewFromConfig(localstackAWSConfig())

	roleName := testID("theknight-public-role")
	// Principal: "*" — assumable by anyone, not just this account or a
	// specific AWS service. Real AWS requires an ExternalId condition or
	// similar to even create a role this open in some contexts, but IAM
	// itself doesn't forbid it, and it's exactly the misconfiguration
	// publicly_assumable exists to catch.
	trustPolicy := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"sts:AssumeRole"}]}`

	if _, err := client.CreateRole(ctx, &iam.CreateRoleInput{
		RoleName:                 &roleName,
		AssumeRolePolicyDocument: &trustPolicy,
	}); err != nil {
		t.Fatalf("CreateRole: %v", err)
	}
	t.Cleanup(func() {
		client.DeleteRole(ctx, &iam.DeleteRoleInput{RoleName: &roleName})
	})

	resources, err := discoverIAM(ctx, client)
	if err != nil {
		t.Fatalf("discoverIAM() error = %v", err)
	}

	var resource Resource
	found := false
	for _, r := range resources {
		if name, _ := r.Metadata["role_name"].(string); name == roleName {
			resource = r
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("role %s not found among %d discovered roles", roleName, len(resources))
	}

	if got := resource.Metadata["publicly_assumable"]; got != true {
		t.Errorf("publicly_assumable = %v, want true (Principal: \"*\" trust policy)", got)
	}
}

func TestIntegration_DiscoverSecurityGroups_OpenIngress(t *testing.T) {
	ctx := context.Background()
	client := ec2.NewFromConfig(localstackAWSConfig())

	groupName := testID("theknight-open-sg")
	createOut, err := client.CreateSecurityGroup(ctx, &ec2.CreateSecurityGroupInput{
		GroupName:   &groupName,
		Description: aws.String("theknight integration test"),
	})
	if err != nil {
		t.Fatalf("CreateSecurityGroup: %v", err)
	}
	groupID := aws.ToString(createOut.GroupId)
	t.Cleanup(func() {
		client.DeleteSecurityGroup(ctx, &ec2.DeleteSecurityGroupInput{GroupId: &groupID})
	})

	if _, err := client.AuthorizeSecurityGroupIngress(ctx, &ec2.AuthorizeSecurityGroupIngressInput{
		GroupId: &groupID,
		IpPermissions: []ec2types.IpPermission{
			{
				IpProtocol: aws.String("tcp"),
				FromPort:   aws.Int32(22),
				ToPort:     aws.Int32(22),
				IpRanges:   []ec2types.IpRange{{CidrIp: aws.String("0.0.0.0/0")}},
			},
			{
				IpProtocol: aws.String("tcp"),
				FromPort:   aws.Int32(8080),
				ToPort:     aws.Int32(8080),
				IpRanges:   []ec2types.IpRange{{CidrIp: aws.String("10.0.0.0/8")}},
			},
		},
	}); err != nil {
		t.Fatalf("AuthorizeSecurityGroupIngress: %v", err)
	}

	resources, err := discoverSecurityGroups(ctx, client, "us-east-1")
	if err != nil {
		t.Fatalf("discoverSecurityGroups() error = %v", err)
	}

	resource := findResourceByID(t, resources, groupID)
	ports, _ := resource.Metadata["open_ingress_ports"].([]int32)
	if len(ports) != 1 || ports[0] != 22 {
		t.Errorf("open_ingress_ports = %v, want [22] (the internal-only 8080 rule must not be flagged)", ports)
	}
	if got := resource.Metadata["open_all_ports"]; got != false {
		t.Errorf("open_all_ports = %v, want false", got)
	}
}

// requireOnlyKnownLocalStackGap asserts that discoverS3's returned error,
// if any, is exactly the GetBucketPolicyStatus gap in LocalStack Community
// ("not yet implemented or pro feature") for the given bucket — nothing
// else. LocalStack doesn't implement that one S3 call, so every S3
// integration test here expects it to fail while the ACL and Public
// Access Block calls, which LocalStack does support, succeed normally.
// Any other error means something is actually broken, not just missing
// from LocalStack, so this fails loudly rather than swallowing it.
func requireOnlyKnownLocalStackGap(t *testing.T, err error, bucket string) {
	t.Helper()
	if err == nil {
		t.Fatal("discoverS3() error = nil, want the known LocalStack GetBucketPolicyStatus gap — if LocalStack has started supporting it, tighten this test")
	}

	msg := err.Error()
	wantSubstr := fmt.Sprintf("bucket %s: policy status", bucket)
	if !strings.Contains(msg, wantSubstr) || !strings.Contains(msg, "not yet implemented or pro feature") {
		t.Fatalf("discoverS3() error = %v, want only the known LocalStack GetBucketPolicyStatus gap for bucket %s", err, bucket)
	}
}

func findResourceByID(t *testing.T, resources []Resource, id string) Resource {
	t.Helper()
	for _, r := range resources {
		if r.ID == id {
			return r
		}
	}
	t.Fatalf("resource %s not found among %d discovered resources", id, len(resources))
	return Resource{}
}
