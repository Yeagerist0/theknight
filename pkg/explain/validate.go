package explain

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/Yeagerist0/theknight/pkg/rules"
)

// Reason is why a briefing was rejected.
type Reason string

const (
	ReasonEmpty          Reason = "empty"
	ReasonTooLong        Reason = "too_long"
	ReasonCodeOrURL      Reason = "code_or_url"
	ReasonCommand        Reason = "shell_command"
	ReasonInventedIdent  Reason = "invented_identifier"
	ReasonInventedQuote  Reason = "invented_quote"
	ReasonSeverity       Reason = "severity_mismatch"
	ReasonForbiddenClaim Reason = "forbidden_claim"
)

// Rejection is returned by Validate.
type Rejection struct {
	Reason Reason
	Detail string
}

func (r *Rejection) Error() string {
	return fmt.Sprintf("briefing rejected: %s (%s)", r.Reason, r.Detail)
}

// MaxLen caps a briefing. A reviewer should be able to read it in one breath.
const MaxLen = 600

var (
	reARN      = regexp.MustCompile(`arn:[a-z0-9-]*:[a-z0-9-]*:[a-z0-9-]*:[0-9]*:[^\s"',;)]+`)
	reAWSID    = regexp.MustCompile(`\b(?:sg|vpc|subnet|i|ami|vol|eni|igw|rtb|acl)-[0-9a-f]{8,17}\b`)
	reIPv4     = regexp.MustCompile(`\b\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?`)
	reIPv6     = regexp.MustCompile(`::/0`)
	reAccount  = regexp.MustCompile(`\b\d{12}\b`)
	reNumber   = regexp.MustCompile(`\b\d{2,5}\b`)
	reQuoted   = regexp.MustCompile(`"([^"\n]{1,200})"`)
	reSeverity = regexp.MustCompile(`(?i)\b(critical|high|medium|low)\b`)
	reCodeURL  = regexp.MustCompile("(?i)```|`|https?://|www\\.|\\]\\(|<[a-z/!]|[a-z]+:[^\\s]*//")
	// A CLI command, not prose: "AWS account" must pass, "aws ec2 revoke-..." must not.
	// The aws part is case-sensitive lowercase and needs a real service name.
	reCommand = regexp.MustCompile(`\baws\s+(?:s3api|s3|ec2|iam|sts|ssm|kms|lambda|rds|cloudformation|configure)\b|(?i:\bterraform\s+(?:apply|destroy)\b|\bsudo\b|\brm\s+-|\bcurl\s|\bchmod\s)`)
	reClaim   = regexp.MustCompile(`(?i)\b(breach(ed|es)?|exploited|compromised|exfiltrat\w*|was attacked|has been (accessed|leaked|abused)|already (remediated|fixed|resolved|mitigated))\b`)
	reDismiss = regexp.MustCompile(`(?i)(\bbenign\b|false[- ]positive|\bno action\b|safe to ignore|can be ignored|\bsuppress\w*|do[- ]not[- ]escalate|\boverride\w*|authorized under|\bnot a (risk|concern|issue)\b)`)
)

// facts is the lower-cased text a briefing may draw identifiers from: only the
// finding itself. Resource metadata is deliberately excluded: it is neither
// shown to the model nor allowed as a source of claims.
func facts(f rules.Finding) string {
	return strings.ToLower(strings.Join([]string{
		f.RuleID, string(f.Severity), f.Title, f.Description, f.Resource.ID, f.Resource.Type, f.Resource.Region,
	}, "\n"))
}

// Validate checks that a model-written briefing is grounded in the finding. It
// is deliberately strict: a rejection falls back to the deterministic
// explanation, which is always safe, so a false rejection costs a nicer
// sentence and a false acceptance costs a misleading reviewer.
//
// It checks, in order: non-empty and short; no code, URLs or commands; every
// ARN, AWS id, IP/CIDR, account id and 2-5 digit number appears in the finding;
// every double-quoted string appears in the finding; any severity word equals
// the finding's severity; no claims of exploitation; no dismissal language.
// It does NOT prove the prose is true, only that it adds no unsupported facts.
func Validate(f rules.Finding, text string) error {
	text = strings.TrimSpace(text)
	if text == "" {
		return &Rejection{ReasonEmpty, "no text"}
	}
	if len(text) > MaxLen {
		return &Rejection{ReasonTooLong, fmt.Sprintf("%d chars, limit %d", len(text), MaxLen)}
	}
	if m := reCodeURL.FindString(text); m != "" {
		return &Rejection{ReasonCodeOrURL, m}
	}
	if m := reCommand.FindString(text); m != "" {
		return &Rejection{ReasonCommand, m}
	}
	known := facts(f)
	masked := text
	for _, re := range []*regexp.Regexp{reARN, reAWSID, reIPv4, reIPv6, reAccount} {
		for _, tok := range re.FindAllString(masked, -1) {
			if !strings.Contains(known, strings.ToLower(tok)) {
				return &Rejection{ReasonInventedIdent, tok}
			}
		}
		masked = re.ReplaceAllString(masked, " ")
	}
	for _, tok := range reNumber.FindAllString(masked, -1) {
		if !strings.Contains(known, tok) {
			return &Rejection{ReasonInventedIdent, tok}
		}
	}
	for _, m := range reQuoted.FindAllStringSubmatch(text, -1) {
		if !strings.Contains(known, strings.ToLower(m[1])) {
			return &Rejection{ReasonInventedQuote, m[1]}
		}
	}
	if st := Steering(f, text); len(st) > 0 {
		return &st[0]
	}
	return nil
}

// Steering reports the behavioural problems in text: a severity word other than
// the finding's, a claim of exploitation, or dismissal language. It is the part
// of Validate that detects a briefing that has been talked into something.
// Callers that want to judge only the model's own words (not a hostile name it
// merely quotes) should remove the quoted name before calling it.
func Steering(f rules.Finding, text string) []Rejection {
	var out []Rejection
	for _, w := range reSeverity.FindAllString(text, -1) {
		if strings.ToLower(w) != string(f.Severity) {
			out = append(out, Rejection{ReasonSeverity, fmt.Sprintf("says %q, finding is %s", w, f.Severity)})
			break
		}
	}
	if m := reClaim.FindString(text); m != "" {
		out = append(out, Rejection{ReasonForbiddenClaim, m})
	}
	if m := reDismiss.FindString(text); m != "" {
		out = append(out, Rejection{ReasonForbiddenClaim, m})
	}
	return out
}
