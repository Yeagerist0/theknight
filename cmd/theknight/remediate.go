package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

func newRemediateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "remediate",
		Short: "Generate a Terraform fix + PR for a given finding",
		RunE: func(cmd *cobra.Command, args []string) error {
			return fmt.Errorf("remediate: not implemented yet")
		},
	}

	return cmd
}
