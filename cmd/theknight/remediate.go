package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/Yeagerist0/theknight/internal/githubpr"
	"github.com/Yeagerist0/theknight/internal/remediate"
	"github.com/Yeagerist0/theknight/pkg/awsclient"
	"github.com/Yeagerist0/theknight/pkg/rules"
	"github.com/Yeagerist0/theknight/pkg/scanner"
)

func newRemediateCmd() *cobra.Command {
	var (
		profile    string
		region     string
		severity   string
		createPR   bool
		repoFlag   string
		baseBranch string
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

			if severity != "" {
				min, err := rules.ParseSeverity(severity)
				if err != nil {
					return err
				}
				findings = rules.Filter(findings, min)
			}

			if len(findings) == 0 {
				fmt.Fprintln(out, "no findings.")
				return nil
			}

			if createPR {
				return runCreatePR(cmd, repoFlag, baseBranch, findings)
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
	cmd.Flags().StringVar(&severity, "severity", "", "minimum severity to include: low|medium|high|critical (default: all)")
	cmd.Flags().BoolVar(&createPR, "create-pr", false, "open a real pull request with the fixes instead of printing them (requires --repo and GITHUB_TOKEN)")
	cmd.Flags().StringVar(&repoFlag, "repo", "", "GitHub repo to open the PR against, as owner/name (required with --create-pr)")
	cmd.Flags().StringVar(&baseBranch, "base-branch", "", "branch to open the PR against (default: the repo's default branch)")

	return cmd
}

// runCreatePR generates a fix for every finding and opens one pull request
// containing all of them. The GitHub token comes from GITHUB_TOKEN only —
// never a CLI flag, for the same reason AWS credentials never are: a flag
// value leaks into shell history and any process listing (ps aux).
func runCreatePR(cmd *cobra.Command, repoFlag, baseBranch string, findings []rules.Finding) error {
	out := cmd.OutOrStdout()
	errOut := cmd.ErrOrStderr()

	owner, repo, err := parseRepo(repoFlag)
	if err != nil {
		return err
	}

	token := os.Getenv("GITHUB_TOKEN")
	if token == "" {
		return fmt.Errorf("--create-pr requires a GITHUB_TOKEN environment variable (a personal access token with Contents and Pull requests write scope on %s/%s)", owner, repo)
	}

	var fixes []githubpr.FileFix
	for _, f := range findings {
		fix, ok, err := remediate.Generate(f)
		if err != nil {
			fmt.Fprintf(errOut, "warning: rendering fix for %s (%s): %v\n", f.RuleID, f.Resource.ID, err)
			continue
		}
		if !ok {
			fmt.Fprintf(errOut, "no remediation template yet for rule %q (%s)\n", f.RuleID, f.Resource.ID)
			continue
		}
		fixes = append(fixes, githubpr.FileFix{Path: githubpr.FixFilePath(f), Fix: fix})
	}

	if len(fixes) == 0 {
		fmt.Fprintln(out, "no fixes with a registered template — nothing to open a PR for.")
		return nil
	}

	client := githubpr.New(token)
	url, err := client.CreatePR(cmd.Context(), owner, repo, baseBranch, fixes)
	if err != nil {
		return fmt.Errorf("creating pull request: %w", err)
	}

	fmt.Fprintf(out, "opened %s (%d fix(es))\n", url, len(fixes))
	return nil
}

func parseRepo(repoFlag string) (owner, repo string, err error) {
	if repoFlag == "" {
		return "", "", fmt.Errorf("--repo is required with --create-pr (format: owner/name)")
	}
	owner, repo, ok := strings.Cut(repoFlag, "/")
	if !ok || owner == "" || repo == "" {
		return "", "", fmt.Errorf("--repo must be in owner/name format, got %q", repoFlag)
	}
	return owner, repo, nil
}
