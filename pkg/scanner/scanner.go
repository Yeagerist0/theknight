// Package scanner discovers AWS resources relevant to misconfiguration
// checks (S3 buckets, IAM roles, EC2 security groups) via the AWS APIs.
package scanner

import (
	"context"
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"github.com/Yeagerist0/theknight/pkg/awsclient"
)

// Resource is a normalized, provider-agnostic view of a scanned cloud
// resource. Rule evaluation operates on this type, not raw AWS SDK structs,
// so that GCP/Azure support (V2) only requires a new scanner, not new rules.
type Resource struct {
	ID       string         `json:"id"`
	Type     string         `json:"type"`
	Region   string         `json:"region"`
	Metadata map[string]any `json:"metadata"`
}

// Discover enumerates resources across every service TheKnight currently
// understands. A failure in one service (e.g. missing IAM permissions)
// doesn't abort the scan — its error is joined into the returned error and
// discovery continues for the remaining services.
func Discover(ctx context.Context, client *awsclient.Client) ([]Resource, error) {
	var (
		resources []Resource
		errs      []error
	)

	// The account id is needed to read account-level S3 Block Public Access
	// (see discoverS3). A failure here (an unusual permission gap --
	// sts:GetCallerIdentity is normally allowed to everyone) degrades to
	// treating account-level PAB as unconfirmed rather than aborting the
	// whole scan, the same non-fatal pattern every other discovery error
	// here follows.
	accountID, err := callerAccountID(ctx, client.STS())
	if err != nil {
		errs = append(errs, fmt.Errorf("sts: resolving account id: %w", err))
	}

	s3Resources, err := discoverS3(ctx, client.S3(), client.S3Control(), accountID)
	if err != nil {
		errs = append(errs, fmt.Errorf("s3: %w", err))
	}
	resources = append(resources, s3Resources...)

	iamResources, err := discoverIAM(ctx, client.IAM())
	if err != nil {
		errs = append(errs, fmt.Errorf("iam: %w", err))
	}
	resources = append(resources, iamResources...)

	sgResources, err := discoverSecurityGroups(ctx, client.EC2(), client.Region)
	if err != nil {
		errs = append(errs, fmt.Errorf("ec2: %w", err))
	}
	resources = append(resources, sgResources...)

	return resources, errors.Join(errs...)
}

// stsAPI is the subset of *sts.Client callerAccountID needs. Matching the
// concrete client's method signature lets tests substitute a fake instead
// of hitting AWS.
type stsAPI interface {
	GetCallerIdentity(ctx context.Context, params *sts.GetCallerIdentityInput, optFns ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error)
}

func callerAccountID(ctx context.Context, api stsAPI) (string, error) {
	out, err := api.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return "", err
	}
	return aws.ToString(out.Account), nil
}
