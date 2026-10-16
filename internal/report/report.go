// Package report renders findings to a human- or machine-readable format.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"

	"golang.org/x/term"

	"github.com/Yeagerist0/theknight/pkg/rules"
)

// Write renders findings in the requested format ("table" or "json") to w.
// findings is expected to already be in the desired display order —
// rules.Evaluate returns most-severe-first, and Write doesn't re-sort.
func Write(w io.Writer, format string, findings []rules.Finding) error {
	switch format {
	case "json":
		if findings == nil {
			findings = []rules.Finding{} // nil marshals to "null"; consumers expect an array, even an empty one
		}
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
	if len(findings) == 0 {
		_, err := fmt.Fprintln(w, "no findings.")
		return err
	}

	color := colorEnabled(w)

	tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "SEVERITY\tRULE\tRESOURCE\tTITLE")
	for _, f := range findings {
		severity := string(f.Severity)
		if color {
			severity = colorize(f.Severity, severity)
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", severity, f.RuleID, sanitizeCell(f.Resource.ID), f.Title)
	}
	return tw.Flush()
}

// sanitizeCell makes an AWS-returned string safe to print as one table
// cell. RuleID and Title are always static strings this codebase writes
// itself; Resource.ID is the one field in this row built from whatever the
// cloud account calls the resource -- an EC2 security group name allows a
// much looser character set than S3 bucket names or IAM role names (see
// the README's Security section, which already treats an embedded newline
// in a group name as a real attack surface for the Terraform this project
// generates). An embedded tab shifts every later column out of alignment;
// an embedded newline does worse -- it lets the value spill onto what
// reads as a second table row, with attacker-chosen text in the SEVERITY
// position, indistinguishable from a real finding to someone skimming
// scan output in a terminal or a CI log. Collapsing tabs/newlines/carriage
// returns to a single space keeps the string, just not its ability to
// forge table structure.
func sanitizeCell(s string) string {
	return strings.Map(func(r rune) rune {
		switch r {
		case '\t', '\n', '\r':
			return ' '
		}
		return r
	}, s)
}

// colorEnabled reports whether the SEVERITY column should be ANSI
// colorized: only when writing directly to a real terminal (not a pipe, a
// file, or a buffer captured for tests) and NO_COLOR isn't set, per
// https://no-color.org.
func colorEnabled(w io.Writer) bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	return term.IsTerminal(int(f.Fd()))
}

const (
	ansiReset   = "\033[0m"
	ansiBoldRed = "\033[1;31m"
	ansiRed     = "\033[31m"
	ansiYellow  = "\033[33m"
	ansiCyan    = "\033[36m"
)

func colorize(severity rules.Severity, text string) string {
	var code string
	switch severity {
	case rules.SeverityCritical:
		code = ansiBoldRed
	case rules.SeverityHigh:
		code = ansiRed
	case rules.SeverityMedium:
		code = ansiYellow
	case rules.SeverityLow:
		code = ansiCyan
	default:
		return text
	}
	return code + text + ansiReset
}
