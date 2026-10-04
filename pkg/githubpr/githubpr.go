// Package githubpr opens a real pull request containing TheKnight's
// remediation output against a GitHub repository, using the GitHub REST
// API directly — no local git clone, no shelling out to the git binary.
// Every file lands in one new commit on one new branch off the target
// repo's default branch, alongside a PR description summarizing what's
// being fixed. Nothing here ever pushes to an existing branch or merges
// anything: opening the PR is the entire scope, same trust boundary as
// the rest of TheKnight (see the README's Security section) — a human
// still reviews and merges.
package githubpr

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/go-github/v75/github"

	"github.com/Yeagerist0/theknight/pkg/remediate"
	"github.com/Yeagerist0/theknight/pkg/rules"
)

// Client opens remediation PRs via the GitHub API.
type Client struct {
	gh *github.Client
}

// New builds a Client authenticated with a GitHub personal access token
// (fine-grained or classic; needs Contents: Read & write and Pull
// requests: Read & write on the target repo). Deliberately takes the
// token as a parameter rather than reading an env var itself — the
// caller (cmd/theknight) owns exactly how it's sourced, and should never
// accept it as a CLI flag (shell history, process list — same reasoning
// as AWS credentials never being a --secret-key flag).
func New(token string) *Client {
	return &Client{gh: github.NewClient(nil).WithAuthToken(token)}
}

// FileFix is a single generated remediation, plus the repo-relative path
// it should land at.
type FileFix struct {
	Path string
	remediate.Fix
	// Briefing is an optional reviewer briefing written by a model and checked
	// against the finding by package explain. Empty means none was produced.
	Briefing string
}

// FixFilePath derives a safe repo-relative path for a fix from its
// finding. AWS-returned identifiers (an IAM role's Resource.ID is a full
// ARN, slashes and colons included) are run through
// remediate.SafeIdent — building a file path directly from an
// unsanitized AWS string is a path-safety problem, not just a display
// one, the same reasoning that drove the %q-escaping fixes in
// pkg/remediate's Terraform generation.
func FixFilePath(f rules.Finding) string {
	return fmt.Sprintf("theknight-fixes/%s-%s.tf", f.RuleID, remediate.SafeIdent(f.Resource.ID))
}

// CreatePR opens a pull request against owner/repo containing one file
// per fix, in a single new commit on a new branch off the repo's default
// branch (or baseBranch, if non-empty). Returns the PR's HTML URL.
func (c *Client) CreatePR(ctx context.Context, owner, repo, baseBranch string, fixes []FileFix) (string, error) {
	if len(fixes) == 0 {
		return "", fmt.Errorf("no fixes to open a PR for")
	}
	fixes = dedupePaths(fixes)

	if baseBranch == "" {
		repoInfo, _, err := c.gh.Repositories.Get(ctx, owner, repo)
		if err != nil {
			return "", fmt.Errorf("getting repository: %w", err)
		}
		baseBranch = repoInfo.GetDefaultBranch()
	}

	baseRef, _, err := c.gh.Git.GetRef(ctx, owner, repo, "refs/heads/"+baseBranch)
	if err != nil {
		return "", fmt.Errorf("getting base branch ref: %w", err)
	}
	baseCommitSHA := baseRef.GetObject().GetSHA()

	baseCommit, _, err := c.gh.Git.GetCommit(ctx, owner, repo, baseCommitSHA)
	if err != nil {
		return "", fmt.Errorf("getting base commit: %w", err)
	}
	baseTreeSHA := baseCommit.GetTree().GetSHA()

	branchName := fmt.Sprintf("theknight/fixes-%d", time.Now().Unix())
	if _, _, err := c.gh.Git.CreateRef(ctx, owner, repo, github.CreateRef{
		Ref: "refs/heads/" + branchName,
		SHA: baseCommitSHA,
	}); err != nil {
		return "", fmt.Errorf("creating branch %s: %w", branchName, err)
	}

	entries := make([]*github.TreeEntry, 0, len(fixes))
	for _, f := range fixes {
		entries = append(entries, &github.TreeEntry{
			Path:    github.Ptr(f.Path),
			Mode:    github.Ptr("100644"),
			Type:    github.Ptr("blob"),
			Content: github.Ptr(fileContent(f)),
		})
	}

	tree, _, err := c.gh.Git.CreateTree(ctx, owner, repo, baseTreeSHA, entries)
	if err != nil {
		return "", fmt.Errorf("creating tree: %w", err)
	}

	commit, _, err := c.gh.Git.CreateCommit(ctx, owner, repo, github.Commit{
		Message: github.Ptr(commitMessage(fixes)),
		Tree:    tree,
		Parents: []*github.Commit{{SHA: github.Ptr(baseCommitSHA)}},
	}, nil)
	if err != nil {
		return "", fmt.Errorf("creating commit: %w", err)
	}

	if _, _, err := c.gh.Git.UpdateRef(ctx, owner, repo, "refs/heads/"+branchName, github.UpdateRef{
		SHA: commit.GetSHA(),
	}); err != nil {
		return "", fmt.Errorf("updating branch %s: %w", branchName, err)
	}

	pr, _, err := c.gh.PullRequests.Create(ctx, owner, repo, &github.NewPullRequest{
		Title: github.Ptr(prTitle(fixes)),
		Head:  github.Ptr(branchName),
		Base:  github.Ptr(baseBranch),
		Body:  github.Ptr(prBody(fixes)),
	})
	if err != nil {
		return "", fmt.Errorf("creating pull request: %w", err)
	}

	return pr.GetHTMLURL(), nil
}

// dedupePaths returns fixes with Path made unique, preserving order.
// FixFilePath runs an AWS resource name through remediate.SafeIdent, which
// collapses any run of characters outside [a-zA-Z0-9_-] to a single "_" --
// safe for a file path, but not injective. Two distinct, both perfectly
// valid resource names can collapse to the same identifier: an EC2
// security group named "db prod" and one named "db.prod" (AWS's security
// group names allow a much looser character set than S3 bucket names --
// see the README) both become "db_prod". Without this, CreateTree below
// would receive two entries with an identical Path, and GitHub silently
// keeps one and drops the other: a real finding goes missing from the PR
// with no error anywhere, and the reviewer-facing table would still cite
// the dropped finding's resource ID next to the surviving file's content.
// Second and later collisions on the same path get "-2", "-3", ... spliced
// in before the extension; the first occurrence keeps its plain path so
// the common, non-colliding case is unaffected.
func dedupePaths(fixes []FileFix) []FileFix {
	seen := make(map[string]int, len(fixes))
	out := make([]FileFix, len(fixes))
	for i, f := range fixes {
		seen[f.Path]++
		if n := seen[f.Path]; n > 1 {
			f.Path = uniquifyPath(f.Path, n)
		}
		out[i] = f
	}
	return out
}

// uniquifyPath inserts "-n" before path's final extension (if it has one)
// or appends it otherwise.
func uniquifyPath(path string, n int) string {
	ext := ""
	if i := strings.LastIndex(path, "."); i > strings.LastIndex(path, "/") {
		path, ext = path[:i], path[i:]
	}
	return fmt.Sprintf("%s-%d%s", path, n, ext)
}

func fileContent(f FileFix) string {
	return fmt.Sprintf("# %s: %s\n# %s\n\n%s", f.Finding.RuleID, f.Finding.Resource.ID, f.Explanation, f.Terraform)
}

func commitMessage(fixes []FileFix) string {
	return fmt.Sprintf("theknight: remediate %d finding(s)", len(fixes))
}

func prTitle(fixes []FileFix) string {
	if len(fixes) == 1 {
		return fmt.Sprintf("theknight: fix %s on %s", fixes[0].Finding.RuleID, fixes[0].Finding.Resource.ID)
	}
	return fmt.Sprintf("theknight: fix %d misconfigurations", len(fixes))
}

func prBody(fixes []FileFix) string {
	var b strings.Builder
	b.WriteString("Opened by `theknight remediate --create-pr`. Every file below is generated — review before merging; nothing here has been applied.\n\n")
	b.WriteString("| Severity | Rule | Resource | File |\n")
	b.WriteString("| --- | --- | --- | --- |\n")
	for _, f := range fixes {
		fmt.Fprintf(&b, "| %s | `%s` | `%s` | `%s` |\n", f.Finding.Severity, f.Finding.RuleID, f.Finding.Resource.ID, f.Path)
	}
	var briefed bool
	for _, f := range fixes {
		if f.Briefing == "" {
			continue
		}
		if !briefed {
			b.WriteString("\n### Reviewer briefings\n\nAI-assisted, and checked against each finding: a briefing is dropped if it adds an identifier or quote the finding does not contain, contradicts its severity, or claims exploitation. The fixes above are generated deterministically, not by a model.\n\n")
			briefed = true
		}
		fmt.Fprintf(&b, "- `%s`: %s\n", f.Finding.Resource.ID, f.Briefing)
	}
	return b.String()
}
