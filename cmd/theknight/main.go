package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var version = "0.0.1-dev"

func main() {
	if err := newRootCmd().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:     "theknight",
		Short:   "TheKnight finds cloud misconfigurations and ships the fix as a PR",
		Version: version,
	}

	root.AddCommand(newScanCmd())
	root.AddCommand(newRemediateCmd())

	return root
}
