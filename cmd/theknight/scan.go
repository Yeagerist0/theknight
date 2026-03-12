package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/Yeagerist0/theknight/internal/report"
	"github.com/Yeagerist0/theknight/pkg/awsclient"
	"github.com/Yeagerist0/theknight/pkg/rules"
	"github.com/Yeagerist0/theknight/pkg/scanner"
)

func newScanCmd() *cobra.Command {
	var (
		profile  string
		region   string
		output   string
		severity string
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

			resources, discoverErr := scanner.Discover(ctx, client)
			if discoverErr != nil {
				fmt.Fprintln(cmd.ErrOrStderr(), "warning: some resources could not be scanned:", discoverErr)
			}
			if len(resources) == 0 && discoverErr != nil {
				return fmt.Errorf("discovering resources: %w", discoverErr)
			}

			findings := rules.Evaluate(resources)

			if severity != "" {
				min, err := rules.ParseSeverity(severity)
				if err != nil {
					return err
				}
				findings = rules.Filter(findings, min)
			}

			return report.Write(cmd.OutOrStdout(), output, findings)
		},
	}

	cmd.Flags().StringVar(&profile, "profile", "", "AWS named profile to use")
	cmd.Flags().StringVar(&region, "region", "us-east-1", "AWS region to scan")
	cmd.Flags().StringVar(&output, "output", "table", "output format: table|json")
	cmd.Flags().StringVar(&severity, "severity", "", "minimum severity to include: low|medium|high|critical (default: all)")

	return cmd
}
