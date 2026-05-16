// Package report renders findings to a human- or machine-readable format.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"text/tabwriter"

	"github.com/Yeagerist0/theknight/internal/rules"
)

// Write renders findings in the requested format ("table" or "json") to w.
func Write(w io.Writer, format string, findings []rules.Finding) error {
	switch format {
	case "json":
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(findings)
	case "table", "":
		return writeTable(w, findings)
	default:
		return fmt.Errorf("unknown output format %q", format)
	}
}

func writeTable(w io.Writer, findings []rules.Finding) error {
	tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "SEVERITY\tRULE\tRESOURCE\tTITLE")
	for _, f := range findings {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", f.Severity, f.RuleID, f.Resource.ID, f.Title)
	}
	return tw.Flush()
}
