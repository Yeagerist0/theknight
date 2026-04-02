package githubpr

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/google/go-github/v75/github"

	"github.com/Yeagerist0/theknight/internal/remediate"
	"github.com/Yeagerist0/theknight/internal/rules"
	"github.com/Yeagerist0/theknight/internal/scanner"
)

// newTestClient points a real *github.Client at an httptest.Server
// instead of api.github.com — the same pattern go-github's own test
// suite uses. Using the real client (not a hand-rolled interface fake)
// means these tests exercise the actual request encoding, not our
// assumptions about it.
func newTestClient(t *testing.T, handler http.Handler) *Client {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	gh := github.NewClient(nil)
	base, err := url.Parse(server.URL + "/")
	if err != nil {
		t.Fatalf("parsing test server URL: %v", err)
	}
	gh.BaseURL = base
	gh.UploadURL = base

	return &Client{gh: gh}
}

func sampleFixes() []FileFix {
	return []FileFix{
		{
			Path: "theknight-fixes/s3-public-read-my-bucket.tf",
			Fix: remediate.Fix{
				Finding: rules.Finding{
					RuleID:   "s3-public-read",
					Severity: rules.SeverityCritical,
					Resource: scanner.Resource{ID: "my-bucket", Type: "aws_s3_bucket"},
				},
				Explanation: "Bucket is public.",
				Terraform:   `resource "aws_s3_bucket_public_access_block" "my-bucket" {}`,
			},
		},
	}
}

// mockGitHubHandler serves the exact sequence of API calls CreatePR
// makes, in order, for the "baseBranch unset, auto-detect default
// branch" path. Each handler asserts it received the request it
// expected and returns a canned response.
func mockGitHubHandler(t *testing.T, opts struct {
	skipRepoGet bool
}) http.Handler {
	t.Helper()

	mux := http.NewServeMux()

	mux.HandleFunc("GET /repos/acme/infra", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(t, w, github.Repository{DefaultBranch: github.Ptr("main")})
	})

	mux.HandleFunc("GET /repos/acme/infra/git/ref/heads/main", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(t, w, github.Reference{
			Ref:    github.Ptr("refs/heads/main"),
			Object: &github.GitObject{SHA: github.Ptr("base-commit-sha"), Type: github.Ptr("commit")},
		})
	})

	mux.HandleFunc("GET /repos/acme/infra/git/commits/base-commit-sha", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(t, w, github.Commit{
			SHA:  github.Ptr("base-commit-sha"),
			Tree: &github.Tree{SHA: github.Ptr("base-tree-sha")},
		})
	})

	mux.HandleFunc("POST /repos/acme/infra/git/refs", func(w http.ResponseWriter, r *http.Request) {
		var body github.CreateRef
		mustDecode(t, r, &body)
		if !strings.HasPrefix(body.Ref, "refs/heads/theknight/fixes-") {
			t.Errorf("CreateRef.Ref = %q, want prefix refs/heads/theknight/fixes-", body.Ref)
		}
		if body.SHA != "base-commit-sha" {
			t.Errorf("CreateRef.SHA = %q, want base-commit-sha", body.SHA)
		}
		writeJSON(t, w, github.Reference{Ref: github.Ptr(body.Ref), Object: &github.GitObject{SHA: github.Ptr(body.SHA)}})
	})

	mux.HandleFunc("POST /repos/acme/infra/git/trees", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			BaseTree string              `json:"base_tree"`
			Tree     []*github.TreeEntry `json:"tree"`
		}
		mustDecode(t, r, &body)
		if body.BaseTree != "base-tree-sha" {
			t.Errorf("CreateTree base_tree = %q, want base-tree-sha", body.BaseTree)
		}
		if len(body.Tree) != 1 {
			t.Fatalf("CreateTree entries = %d, want 1", len(body.Tree))
		}
		if body.Tree[0].GetPath() != "theknight-fixes/s3-public-read-my-bucket.tf" {
			t.Errorf("tree entry path = %q, want theknight-fixes/s3-public-read-my-bucket.tf", body.Tree[0].GetPath())
		}
		if !strings.Contains(body.Tree[0].GetContent(), "aws_s3_bucket_public_access_block") {
			t.Errorf("tree entry content missing generated Terraform: %q", body.Tree[0].GetContent())
		}
		writeJSON(t, w, github.Tree{SHA: github.Ptr("new-tree-sha")})
	})

	mux.HandleFunc("POST /repos/acme/infra/git/commits", func(w http.ResponseWriter, r *http.Request) {
		// go-github's CreateCommit flattens commit.Tree/*Tree and
		// commit.Parents/[]*Commit down to bare SHA strings on the wire
		// (see createCommit in git_commits.go) — the request body doesn't
		// match the public github.Commit struct's own JSON tags.
		var body struct {
			Tree    string   `json:"tree"`
			Parents []string `json:"parents"`
		}
		mustDecode(t, r, &body)
		if body.Tree != "new-tree-sha" {
			t.Errorf("CreateCommit tree SHA = %q, want new-tree-sha", body.Tree)
		}
		if len(body.Parents) != 1 || body.Parents[0] != "base-commit-sha" {
			t.Errorf("CreateCommit parents = %v, want [base-commit-sha]", body.Parents)
		}
		writeJSON(t, w, github.Commit{SHA: github.Ptr("new-commit-sha")})
	})

	mux.HandleFunc("PATCH /repos/acme/infra/git/refs/heads/", func(w http.ResponseWriter, r *http.Request) {
		var body github.UpdateRef
		mustDecode(t, r, &body)
		if body.SHA != "new-commit-sha" {
			t.Errorf("UpdateRef.SHA = %q, want new-commit-sha", body.SHA)
		}
		writeJSON(t, w, github.Reference{Object: &github.GitObject{SHA: github.Ptr(body.SHA)}})
	})

	mux.HandleFunc("POST /repos/acme/infra/pulls", func(w http.ResponseWriter, r *http.Request) {
		var body github.NewPullRequest
		mustDecode(t, r, &body)
		if body.GetBase() != "main" {
			t.Errorf("NewPullRequest.Base = %q, want main", body.GetBase())
		}
		if !strings.HasPrefix(body.GetHead(), "theknight/fixes-") {
			t.Errorf("NewPullRequest.Head = %q, want prefix theknight/fixes-", body.GetHead())
		}
		if !strings.Contains(body.GetBody(), "s3-public-read") {
			t.Errorf("PR body missing rule ID: %q", body.GetBody())
		}
		writeJSON(t, w, github.PullRequest{
			HTMLURL: github.Ptr("https://github.com/acme/infra/pull/42"),
			Number:  github.Ptr(42),
		})
	})

	return mux
}

func writeJSON(t *testing.T, w http.ResponseWriter, v any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		t.Fatalf("encoding test response: %v", err)
	}
}

func mustDecode(t *testing.T, r *http.Request, v any) {
	t.Helper()
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		t.Fatalf("decoding request body: %v", err)
	}
}

func TestCreatePR_FullSequence(t *testing.T) {
	handler := mockGitHubHandler(t, struct{ skipRepoGet bool }{})
	client := newTestClient(t, handler)

	url, err := client.CreatePR(t.Context(), "acme", "infra", "", sampleFixes())
	if err != nil {
		t.Fatalf("CreatePR() error = %v", err)
	}
	if url != "https://github.com/acme/infra/pull/42" {
		t.Errorf("CreatePR() = %q, want https://github.com/acme/infra/pull/42", url)
	}
}

func TestCreatePR_ExplicitBaseBranchSkipsRepoLookup(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /repos/acme/infra", func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("Repositories.Get should not be called when baseBranch is explicit")
	})
	mux.HandleFunc("GET /repos/acme/infra/git/ref/heads/release", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(t, w, github.Reference{
			Object: &github.GitObject{SHA: github.Ptr("base-commit-sha")},
		})
	})
	mux.HandleFunc("GET /repos/acme/infra/git/commits/base-commit-sha", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(t, w, github.Commit{Tree: &github.Tree{SHA: github.Ptr("base-tree-sha")}})
	})
	mux.HandleFunc("POST /repos/acme/infra/git/refs", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(t, w, github.Reference{})
	})
	mux.HandleFunc("POST /repos/acme/infra/git/trees", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(t, w, github.Tree{SHA: github.Ptr("new-tree-sha")})
	})
	mux.HandleFunc("POST /repos/acme/infra/git/commits", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(t, w, github.Commit{SHA: github.Ptr("new-commit-sha")})
	})
	mux.HandleFunc("PATCH /repos/acme/infra/git/refs/heads/", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(t, w, github.Reference{})
	})
	mux.HandleFunc("POST /repos/acme/infra/pulls", func(w http.ResponseWriter, r *http.Request) {
		var body github.NewPullRequest
		mustDecode(t, r, &body)
		if body.GetBase() != "release" {
			t.Errorf("NewPullRequest.Base = %q, want release", body.GetBase())
		}
		writeJSON(t, w, github.PullRequest{HTMLURL: github.Ptr("https://github.com/acme/infra/pull/7")})
	})

	client := newTestClient(t, mux)
	if _, err := client.CreatePR(t.Context(), "acme", "infra", "release", sampleFixes()); err != nil {
		t.Fatalf("CreatePR() error = %v", err)
	}
}

func TestCreatePR_NoFixesIsAnError(t *testing.T) {
	client := newTestClient(t, http.NewServeMux())
	if _, err := client.CreatePR(t.Context(), "acme", "infra", "main", nil); err == nil {
		t.Fatal("CreatePR() error = nil, want non-nil for zero fixes")
	}
}

func TestCreatePR_PropagatesAPIErrors(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /repos/acme/infra/git/ref/heads/main", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})

	client := newTestClient(t, mux)
	_, err := client.CreatePR(t.Context(), "acme", "infra", "main", sampleFixes())
	if err == nil {
		t.Fatal("CreatePR() error = nil, want non-nil when the base ref lookup 404s")
	}
	if !strings.Contains(err.Error(), "base branch ref") {
		t.Errorf("error = %v, want it to identify the base-ref lookup as the failing step", err)
	}
}

func TestFixFilePath_SanitizesARNSlashesAndColons(t *testing.T) {
	f := rules.Finding{
		RuleID: "iam-wildcard-action",
		Resource: scanner.Resource{
			ID: "arn:aws:iam::123456789012:role/deploy-role",
		},
	}

	path := FixFilePath(f)

	if strings.Contains(path, "..") {
		t.Errorf("FixFilePath(%+v) = %q, contains \"..\" — path traversal risk", f, path)
	}
	want := fmt.Sprintf("theknight-fixes/iam-wildcard-action-%s.tf", remediate.SafeIdent(f.Resource.ID))
	if path != want {
		t.Errorf("FixFilePath() = %q, want %q", path, want)
	}
	if !strings.HasPrefix(path, "theknight-fixes/") || strings.Count(path, "/") != 1 {
		t.Errorf("FixFilePath() = %q, want exactly one path separator (no nested directories from the ARN's slashes)", path)
	}
}
