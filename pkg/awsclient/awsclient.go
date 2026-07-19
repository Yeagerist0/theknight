// Package awsclient wraps AWS SDK v2 config/session setup so the rest of
// the codebase depends on a small internal interface instead of the SDK
// directly.
package awsclient

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/s3"
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

// S3 constructs an S3 service client from the resolved config.
//
// Deliberately no UsePathStyle override here: path-style addressing is
// what an S3-compatible endpoint like LocalStack needs when accessed
// directly on localhost, but it's the wrong default against real AWS —
// virtual-hosted-style is what production accounts get. That tradeoff
// means this client can't talk to LocalStack's S3 API directly (see
// internal/scanner/integration_test.go, which builds its own path-style
// client instead of going through this constructor).
func (c *Client) S3() *s3.Client { return s3.NewFromConfig(c.Config) }

// IAM constructs an IAM service client from the resolved config. IAM is a
// global service; the client ignores Config.Region.
func (c *Client) IAM() *iam.Client { return iam.NewFromConfig(c.Config) }

// EC2 constructs an EC2 service client from the resolved config.
func (c *Client) EC2() *ec2.Client { return ec2.NewFromConfig(c.Config) }
