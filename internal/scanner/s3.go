package scanner

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

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
	GetBucketPolicy(ctx context.Context, params *s3.GetBucketPolicyInput, optFns ...func(*s3.Options)) (*s3.GetBucketPolicyOutput, error)
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

			// GetBucketPolicyStatus (above) is AWS's own authoritative "is
			// this bucket public via policy" computation — it accounts for
			// nuances (account-level Public Access Block, etc.) this
			// scanner doesn't replicate, so it stays the source of truth
			// for policyPublic itself. What it doesn't say is which
			// permission the public grant covers, so when it says public,
			// the actual policy document is parsed to find out.
			//
			// Defaults here are asymmetric on purpose: policyPublicRead
			// falls back to policyPublic when parsing can't confirm
			// either way, preserving this rule's existing (already
			// shipped) detection behavior. policyPublicWrite only becomes
			// true on positive evidence, never inferred — s3-public-write
			// is new, and overclaiming impact in a security report is
			// worse than under-claiming it.
			policyPublicRead, policyPublicWrite := policyPublic, false
			if policyPublic {
				grantsRead, grantsWrite, permErr := bucketPolicyPermissions(ctx, api, name)
				if permErr != nil {
					errs = append(errs, fmt.Errorf("bucket %s: policy document: %w", name, permErr))
				} else {
					policyPublicRead, policyPublicWrite = grantsRead, grantsWrite
				}
			}
			metadata["policy_public_read"] = policyPublicRead
			metadata["policy_public_write"] = policyPublicWrite
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

// bucketPolicyPermissions parses a bucket's policy document to determine
// which permission (read, write, or both) any Allow statement grants to a
// public principal. Only called once GetBucketPolicyStatus has already
// confirmed the bucket is public via policy — this doesn't re-derive that
// signal, just breaks it down further.
func bucketPolicyPermissions(ctx context.Context, api s3API, name string) (grantsRead, grantsWrite bool, err error) {
	out, err := api.GetBucketPolicy(ctx, &s3.GetBucketPolicyInput{Bucket: &name})
	if err != nil {
		if isAWSErrorCode(err, "NoSuchBucketPolicy") {
			return false, false, nil
		}
		return false, false, err
	}

	stmts, err := parseS3PolicyStatements(aws.ToString(out.Policy))
	if err != nil {
		return false, false, err
	}

	for _, s := range stmts {
		if s.Effect != "Allow" || !s3PrincipalIsPublic(s.Principal) {
			continue
		}
		for _, action := range jsonStringList(s.Action) {
			if s3ActionGrantsRead(action) {
				grantsRead = true
			}
			if s3ActionGrantsWrite(action) {
				grantsWrite = true
			}
		}
	}

	return grantsRead, grantsWrite, nil
}

type s3PolicyStatement struct {
	Effect    string          `json:"Effect"`
	Principal json.RawMessage `json:"Principal"`
	Action    json.RawMessage `json:"Action"`
}

// parseS3PolicyStatements handles the fact that a policy document's
// Statement field is either a single object or an array of objects — the
// same shape IAM policy documents use, but S3 bucket policies are a
// separate type from internal/scanner/iam.go's iamStatement (S3 doesn't
// have a Resource-wildcard equivalent this scanner cares about).
func parseS3PolicyStatements(doc string) ([]s3PolicyStatement, error) {
	var raw struct {
		Statement json.RawMessage `json:"Statement"`
	}
	if err := json.Unmarshal([]byte(doc), &raw); err != nil {
		return nil, err
	}

	var stmts []s3PolicyStatement
	if err := json.Unmarshal(raw.Statement, &stmts); err == nil {
		return stmts, nil
	}

	var single s3PolicyStatement
	if err := json.Unmarshal(raw.Statement, &single); err != nil {
		return nil, err
	}
	return []s3PolicyStatement{single}, nil
}

// s3PrincipalIsPublic reports whether a policy statement's Principal
// grants access to anyone: either the bare wildcard ("Principal": "*") or
// an AWS principal wildcard ("Principal": {"AWS": "*"} or a list
// containing it). Doesn't account for Condition blocks that might narrow
// an otherwise-public principal (e.g. a source-IP restriction) — treating
// Principal: "*" as public regardless of Condition is the same
// conservative baseline AWS's own bucket-policy public-access warnings
// use.
func s3PrincipalIsPublic(raw json.RawMessage) bool {
	if len(raw) == 0 {
		return false
	}

	if slices.Contains(jsonStringList(raw), "*") {
		return true
	}

	var p struct {
		AWS json.RawMessage `json:"AWS"`
	}
	if err := json.Unmarshal(raw, &p); err != nil {
		return false
	}

	return slices.Contains(jsonStringList(p.AWS), "*")
}

func s3ActionGrantsRead(action string) bool {
	switch {
	case action == "*", strings.EqualFold(action, "s3:*"):
		return true
	case strings.HasPrefix(strings.ToLower(action), "s3:get"),
		strings.HasPrefix(strings.ToLower(action), "s3:list"):
		return true
	}
	return false
}

func s3ActionGrantsWrite(action string) bool {
	switch {
	case action == "*", strings.EqualFold(action, "s3:*"):
		return true
	case strings.HasPrefix(strings.ToLower(action), "s3:put"),
		strings.HasPrefix(strings.ToLower(action), "s3:delete"):
		return true
	}
	return false
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
