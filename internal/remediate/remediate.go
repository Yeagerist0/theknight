// Package remediate maps findings to Terraform fix templates. Every
// template renders HCL a reviewer still has to read and merge — nothing
// here is ever applied automatically. That's a deliberate trust boundary,
// not a missing feature (see README).
package remediate

import (
	"regexp"
	"strings"

	"github.com/Yeagerist0/theknight/pkg/rules"
)

// Fix is a rendered remediation for a single Finding: the reasoning a
// reviewer needs, plus the Terraform to apply it.
type Fix struct {
	Finding     rules.Finding
	Explanation string
	Terraform   string
}

type templateFunc func(rules.Finding) (Fix, error)

var registry = map[string]templateFunc{}

// register wires a template to the RemediationID that a rule sets on its
// findings. Called from each template file's init().
func register(remediationID string, fn templateFunc) {
	registry[remediationID] = fn
}

// Generate renders the fix for a finding. ok is false when no template is
// registered yet for the finding's RemediationID — that happens when a
// rule ships before its matching template does, and is not itself an
// error.
func Generate(f rules.Finding) (fix Fix, ok bool, err error) {
	tmpl, found := registry[f.RemediationID]
	if !found {
		return Fix{}, false, nil
	}

	fix, err = tmpl(f)
	return fix, true, err
}

var nonIdentChar = regexp.MustCompile(`[^a-zA-Z0-9_-]+`)

// SafeIdent turns an arbitrary AWS-returned string into a string containing
// only [a-zA-Z0-9_-], never starting with a digit. Used as a Terraform
// local resource identifier here, and reused by internal/githubpr to build
// safe repo file paths from the same untrusted AWS names (an IAM role's
// Resource.ID is a full ARN like "arn:aws:iam::111:role/deploy" — slashes
// and colons included — so building a file path directly from it without
// this treatment is a path-safety problem, not just a display one).
func SafeIdent(name string) string {
	ident := strings.Trim(nonIdentChar.ReplaceAllString(name, "_"), "_")
	if ident == "" {
		return "resource"
	}
	if ident[0] >= '0' && ident[0] <= '9' {
		ident = "_" + ident
	}
	return ident
}
