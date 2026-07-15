package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/Yeagerist0/theknight/internal/awsclient"
	"github.com/Yeagerist0/theknight/internal/report"
	"github.com/Yeagerist0/theknight/internal/rules"
	"github.com/Yeagerist0/theknight/internal/scanner"
)

func newScanCmd() *cobra.Command {
	var (
		profile string
		region  string
		output  string
	)

	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Scan an AWS account for misconfigurations",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()

			client, err := awsclient.New(ctx, profile, region)
			if err != nil {
				return fmt.Errorf("connecting to AWS: %w", err)
			}

			resources, err := scanner.Discover(ctx, client)
			if err != nil {
				return fmt.Errorf("discovering resources: %w", err)
			}

			findings := rules.Evaluate(resources)

			return report.Write(cmd.OutOrStdout(), output, findings)
		},
	}

	cmd.Flags().StringVar(&profile, "profile", "", "AWS named profile to use")
	cmd.Flags().StringVar(&region, "region", "us-east-1", "AWS region to scan")
	cmd.Flags().StringVar(&output, "output", "table", "output format: table|json")

	return cmd
}
