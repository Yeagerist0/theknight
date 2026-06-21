package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/Yeagerist0/theknight/internal/awsclient"
	"github.com/Yeagerist0/theknight/internal/remediate"
	"github.com/Yeagerist0/theknight/internal/rules"
	"github.com/Yeagerist0/theknight/internal/scanner"
)

func newRemediateCmd() *cobra.Command {
	var (
		profile string
		region  string
	)

	cmd := &cobra.Command{
		Use:   "remediate",
		Short: "Scan an AWS account and render the Terraform fix for what it finds",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			out := cmd.OutOrStdout()
			errOut := cmd.ErrOrStderr()

			client, err := awsclient.New(ctx, profile, region)
			if err != nil {
				return fmt.Errorf("connecting to AWS: %w", err)
			}

			resources, discoverErr := scanner.Discover(ctx, client)
			if discoverErr != nil {
				fmt.Fprintln(errOut, "warning: some resources could not be scanned:", discoverErr)
			}
			if len(resources) == 0 && discoverErr != nil {
				return fmt.Errorf("discovering resources: %w", discoverErr)
			}

			findings := rules.Evaluate(resources)
			if len(findings) == 0 {
				fmt.Fprintln(out, "no findings.")
				return nil
			}

			for i, f := range findings {
				fix, ok, err := remediate.Generate(f)
				if err != nil {
					fmt.Fprintf(errOut, "warning: rendering fix for %s (%s): %v\n", f.RuleID, f.Resource.ID, err)
					continue
				}
				if !ok {
					fmt.Fprintf(errOut, "no remediation template yet for rule %q (%s)\n", f.RuleID, f.Resource.ID)
					continue
				}

				if i > 0 {
					fmt.Fprintln(out)
				}
				fmt.Fprintf(out, "# %s: %s\n# %s\n\n%s", f.RuleID, f.Resource.ID, fix.Explanation, fix.Terraform)
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&profile, "profile", "", "AWS named profile to use")
	cmd.Flags().StringVar(&region, "region", "us-east-1", "AWS region to scan")

	return cmd
}
