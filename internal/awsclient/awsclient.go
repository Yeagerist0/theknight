// Package awsclient wraps AWS SDK v2 config/session setup so the rest of
// the codebase depends on a small internal interface instead of the SDK
// directly.
package awsclient

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
)

// Client holds the resolved AWS config used to construct per-service SDK
// clients (S3, IAM, EC2, ...) on demand.
type Client struct {
	Config aws.Config
	Region string
}

// New resolves AWS credentials/config for the given profile and region,
// following the standard SDK credential chain when profile is empty.
func New(ctx context.Context, profile, region string) (*Client, error) {
	opts := []func(*config.LoadOptions) error{
		config.WithRegion(region),
	}
	if profile != "" {
		opts = append(opts, config.WithSharedConfigProfile(profile))
	}

	cfg, err := config.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("loading AWS config: %w", err)
	}

	return &Client{Config: cfg, Region: region}, nil
}
