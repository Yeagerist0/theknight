// Package scanner discovers AWS resources relevant to misconfiguration
// checks (S3 buckets, IAM roles, EC2 security groups) via the AWS APIs.
package scanner

import (
	"context"
	"errors"
	"fmt"

	"github.com/Yeagerist0/theknight/internal/awsclient"
)

// Resource is a normalized, provider-agnostic view of a scanned cloud
// resource. Rule evaluation operates on this type, not raw AWS SDK structs,
// so that GCP/Azure support (V2) only requires a new scanner, not new rules.
type Resource struct {
	ID       string
	Type     string
	Region   string
	Metadata map[string]any
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

	s3Resources, err := discoverS3(ctx, client.S3())
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
