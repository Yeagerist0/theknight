package scanner

import (
	"context"
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	smithy "github.com/aws/smithy-go"
)

// s3API is the subset of *s3.Client that discoverS3 needs. Matching the
// concrete client's method signatures lets tests substitute a fake instead
// of hitting AWS.
type s3API interface {
	ListBuckets(ctx context.Context, params *s3.ListBucketsInput, optFns ...func(*s3.Options)) (*s3.ListBucketsOutput, error)
	GetBucketAcl(ctx context.Context, params *s3.GetBucketAclInput, optFns ...func(*s3.Options)) (*s3.GetBucketAclOutput, error)
	GetBucketPolicyStatus(ctx context.Context, params *s3.GetBucketPolicyStatusInput, optFns ...func(*s3.Options)) (*s3.GetBucketPolicyStatusOutput, error)
	GetPublicAccessBlock(ctx context.Context, params *s3.GetPublicAccessBlockInput, optFns ...func(*s3.Options)) (*s3.GetPublicAccessBlockOutput, error)
}

const (
	granteeAllUsers           = "http://acs.amazonaws.com/groups/global/AllUsers"
	granteeAuthenticatedUsers = "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"
)

func discoverS3(ctx context.Context, api s3API) ([]Resource, error) {
	out, err := api.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		return nil, fmt.Errorf("listing buckets: %w", err)
	}

	var (
		resources []Resource
		errs      []error
	)

	for _, b := range out.Buckets {
		name := aws.ToString(b.Name)
		if name == "" {
			continue
		}

		// Each signal is collected independently: a bucket where one of the
		// three calls fails (a narrower IAM grant on just that action, an
		// API not implemented by whatever's behind the s3API interface,
		// ...) still gets reported with whatever metadata succeeded, rather
		// than silently dropping the bucket from the scan entirely. Rules
		// reading a missing key get Go's zero value (false) for that
		// signal — see internal/rules/s3.go for why that default leans
		// toward false positives over false negatives.
		metadata := map[string]any{}

		publicRead, publicWrite, err := bucketPublicACL(ctx, api, name)
		if err != nil {
			errs = append(errs, fmt.Errorf("bucket %s: acl: %w", name, err))
		} else {
			metadata["acl_public_read"] = publicRead
			metadata["acl_public_write"] = publicWrite
		}

		policyPublic, err := bucketPolicyPublic(ctx, api, name)
		if err != nil {
			errs = append(errs, fmt.Errorf("bucket %s: policy status: %w", name, err))
		} else {
			metadata["policy_public"] = policyPublic
		}

		blocked, err := publicAccessBlockEnabled(ctx, api, name)
		if err != nil {
			errs = append(errs, fmt.Errorf("bucket %s: public access block: %w", name, err))
		} else {
			metadata["public_access_block_enabled"] = blocked
		}

		resources = append(resources, Resource{
			ID:       name,
			Type:     "aws_s3_bucket",
			Region:   aws.ToString(b.BucketRegion),
			Metadata: metadata,
		})
	}

	return resources, errors.Join(errs...)
}

func bucketPublicACL(ctx context.Context, api s3API, name string) (publicRead, publicWrite bool, err error) {
	out, err := api.GetBucketAcl(ctx, &s3.GetBucketAclInput{Bucket: &name})
	if err != nil {
		return false, false, err
	}

	for _, grant := range out.Grants {
		if grant.Grantee == nil {
			continue
		}

		uri := aws.ToString(grant.Grantee.URI)
		if uri != granteeAllUsers && uri != granteeAuthenticatedUsers {
			continue
		}

		switch grant.Permission {
		case types.PermissionRead, types.PermissionFullControl:
			publicRead = true
		}
		switch grant.Permission {
		case types.PermissionWrite, types.PermissionFullControl:
			publicWrite = true
		}
	}

	return publicRead, publicWrite, nil
}

func bucketPolicyPublic(ctx context.Context, api s3API, name string) (bool, error) {
	out, err := api.GetBucketPolicyStatus(ctx, &s3.GetBucketPolicyStatusInput{Bucket: &name})
	if err != nil {
		if isAWSErrorCode(err, "NoSuchBucketPolicy") {
			return false, nil
		}
		return false, err
	}

	if out.PolicyStatus == nil {
		return false, nil
	}
	return aws.ToBool(out.PolicyStatus.IsPublic), nil
}

func publicAccessBlockEnabled(ctx context.Context, api s3API, name string) (bool, error) {
	out, err := api.GetPublicAccessBlock(ctx, &s3.GetPublicAccessBlockInput{Bucket: &name})
	if err != nil {
		if isAWSErrorCode(err, "NoSuchPublicAccessBlockConfiguration") {
			return false, nil
		}
		return false, err
	}

	cfg := out.PublicAccessBlockConfiguration
	if cfg == nil {
		return false, nil
	}

	return aws.ToBool(cfg.BlockPublicAcls) &&
		aws.ToBool(cfg.BlockPublicPolicy) &&
		aws.ToBool(cfg.IgnorePublicAcls) &&
		aws.ToBool(cfg.RestrictPublicBuckets), nil
}

func isAWSErrorCode(err error, code string) bool {
	var apiErr smithy.APIError
	return errors.As(err, &apiErr) && apiErr.ErrorCode() == code
}
