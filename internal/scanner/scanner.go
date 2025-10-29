// Package scanner discovers AWS resources relevant to misconfiguration checks
// (S3 buckets, IAM roles/policies, security groups) via the AWS APIs.
package scanner

import (
	"context"

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

// Discover enumerates resources across the services TheKnight currently
// understands. It fans out per-service and aggregates results.
func Discover(ctx context.Context, client *awsclient.Client) ([]Resource, error) {
	// TODO: S3 buckets, IAM roles/policies, EC2 security groups.
	return nil, nil
}
