# Roadmap

## MVP — AWS CLI scanner + remediation PR generator (4-6 weeks)

Goal: a real, runnable tool. This is the portfolio artifact.

**MVP complete as of 2026-07-17.** Everything below is done, unit +
integration tested (LocalStack), and pushed. What's left for this repo is
V1/V2, not MVP polish.

**Security pass done 2026-07-17**: fixed a real HCL-injection path (EC2
security group name interpolated unescaped into generated Terraform —
see README's Security section), patched 5 stdlib CVEs via a Go toolchain
bump (`govulncheck` clean), documented the read-only guarantee and
minimal IAM policy. Not a one-time checkbox — any new AWS-returned string
embedded in future rules/templates needs the same `%q` treatment, and
`govulncheck ./...` is worth rerunning periodically as new stdlib CVEs
get disclosed.

**Restructure, 2026-07-18**: moved `awsclient`/`scanner`/`rules` from
`internal/` to `pkg/` (mechanical rename, no logic change). Found while
starting the theknight-server hosted backend: Go's `internal/` visibility
rule means a package there can only be imported by code inside the same
module, so a *separate* repo/module (theknight-server) genuinely cannot
import `theknight/internal/scanner` at all, not even as a declared
dependency — the compiler rejects it. Since the whole open-core premise
is the hosted backend reusing this detection logic rather than
reimplementing it, this had to move. `remediate`/`report`/`githubpr`
stay `internal/` since the backend doesn't need them yet.

- [x] `pkg/scanner`: discovery for S3 buckets, IAM roles/policies, EC2
      security groups
- [x] `pkg/rules`: first rule set
  - [x] `s3-public-read` — public bucket ACL or policy, unless a Public
        Access Block configuration restricts it
  - [x] `s3-public-write` — ACL grant, or a policy document Allow
        statement with a public Principal granting an `s3:Put*`/
        `s3:Delete*`/`s3:*` action (parsed the same way IAM policy
        documents are, once `GetBucketPolicyStatus` confirms the bucket
        is public via policy at all)
  - [x] `iam-wildcard-action` — `"Action": "*"` in an Allow statement,
        inline or attached managed policy
  - [x] `iam-wildcard-resource` — `"Resource": "*"`, same policy sources
  - [x] `sg-open-ingress` — security group open to `0.0.0.0/0`/`::/0` on a
        sensitive port, or all ports via protocol `-1`
- [x] Severity scoring that accounts for exposure — `sg-open-ingress`:
      Critical for protocol `-1` (all ports), High for a specific port;
      `iam-wildcard-action`/`iam-wildcard-resource`: Critical when the
      role's trust policy allows a wildcard or cross-account principal,
      High when scoped to an AWS service or same account (account ID
      derived from the role's own ARN, no extra STS call)
- [x] `internal/remediate`: Terraform templates keyed by `RemediationID` —
      `s3-block-public-access` (covers both read and write findings),
      `iam-scope-actions` / `iam-scope-resources` (both point at IAM
      Access Analyzer instead of guessing a minimal action/resource set —
      no safe static default exists for either), `sg-restrict-ingress-cidr`
- [x] `theknight remediate`: scans, evaluates, and renders the Terraform +
      explanation for every finding with a registered template to stdout
      by default, or via `--create-pr` opens a real GitHub PR (see V1
      below — this was originally scoped as stdout-only for MVP, pulled
      forward once the CLI+PAT version turned out not to need any hosted
      infrastructure)
- [x] `--severity` filter flag on `scan` and `remediate` — threshold
      filter (`--severity high` shows high and critical), backed by
      `rules.Filter`/`rules.ParseSeverity`
- [x] table/JSON output polish — `rules.Evaluate` sorts findings
      most-severe-first (stable, so same-severity findings keep their
      discovery order); JSON gets proper camelCase field tags instead of
      raw Go struct names (`ruleId` not `RuleID`) and always emits `[]`
      for zero findings, never the bare JSON `null` a nil slice marshals
      to by default (a real bug caught by testing against the live CLI,
      not just decode-and-check-length unit tests, which silently accept
      `null` for a slice target); table output prints `no findings.`
      instead of a bare header row, and ANSI-colorizes the SEVERITY
      column by severity when writing to a real terminal, respecting
      `NO_COLOR` and auto-disabling for piped/redirected output
- [x] Tests against recorded/fixture AWS API responses (no live account
      needed to run CI) — fake `s3API`/`iamAPI`/`ec2API` implementations,
      42 test cases covering discovery, rule evaluation, and remediation
- [x] Integration tests against real AWS API wiring (not just fakes) —
      `pkg/scanner/integration_test.go` (`//go:build integration`)
      provisions real S3/IAM/EC2 resources against LocalStack and runs the
      actual discovery functions. `make integration-test` / CI can run
      this as a slower, Docker-gated tier alongside the fast fixture tests
- [x] README demo GIF (`docs/assets/demo.gif`) — recorded with
      asciinema + agg against the actual compiled binary pointed at
      LocalStack via `AWS_ENDPOINT_URL` (works with zero code changes for
      IAM/EC2; S3 needs path-style addressing LocalStack requires on
      localhost, which the production S3 client intentionally doesn't set
      — see the `s3.NewFromConfig` comment in `pkg/awsclient` — so
      the recording demos IAM + EC2 only, not S3)
- [x] S3 bucket policy document parsing — `bucketPolicyPermissions` in
      `pkg/scanner/s3.go`, mirroring the IAM policy parsing pattern.
      `policy_public_read`/`policy_public_write` are only trusted on
      positive parsing evidence for write (never assumed — overclaiming
      impact is worse than underclaiming it); read falls back to the
      generic `policy_public` signal when parsing isn't possible,
      preserving prior behavior. Integration-tested by calling
      `bucketPolicyPermissions` directly against LocalStack, since the
      normal `discoverS3` gate (`GetBucketPolicyStatus`) is a known
      LocalStack Community gap that would otherwise block coverage of
      code that doesn't actually depend on it

## V1 — hosted product

- [x] **GitHub PR creation (CLI + PAT slice, 2026-07-17)** —
      `internal/githubpr` opens a real PR via the GitHub REST API: one
      new branch off the repo's default branch, one commit (blob+tree+
      commit via the Git Data API, not N separate per-file commits), one
      PR with a markdown table summarizing every finding. `--create-pr`
      / `--repo` / `--base-branch` flags on `theknight remediate`;
      `GITHUB_TOKEN` from the environment only, same reasoning as AWS
      credentials never being a CLI flag. File paths run AWS-returned
      resource IDs through `remediate.SafeIdent` (exported from the
      Terraform-identifier sanitizer already built for the HCL-injection
      fix) — an IAM Resource.ID is a full ARN with slashes and colons,
      so building a repo path directly from it is a path-safety problem,
      not just a display one. Tested against an `httptest.Server` +
      `Client.BaseURL` override (go-github's own documented test
      pattern — caught a real bug where a mock handler assumed
      `CreateCommit`'s wire format matched the public `Commit` struct
      instead of go-github's private flattened-to-SHA-strings format)
      and verified against a real throwaway GitHub repo (PR:
      https://github.com/Yeagerist0/theknight-pr-test/pull/1).
      **Not done**: the actual GitHub App (OAuth install flow +
      webhooks) this item originally specified — that still needs a
      hosted backend and is tracked separately below. This is the
      CLI-only substitute that delivers the same user-visible outcome
      without one.
- [x] **Backend core (scheduled scanning, trend reporting, multi-account,
      2026-07-19)** — a separate hosted-product repo,
      [theknight-server](https://github.com/Yeagerist0/theknight-server),
      depends on this repo's `pkg/awsclient` `pkg/scanner` `pkg/rules` as
      a library (this is why the restructuring above happened — Go's
      `internal/` visibility rule blocks a second module from importing
      them at all). It adds: Postgres-backed multi-tenant orgs/API
      keys/connected AWS accounts; per-account cron scheduling
      (`robfig/cron`) that assumes each customer's IAM role via STS with
      the standard external-ID confused-deputy mitigation; scan
      persistence that reconciles findings across runs (first-seen /
      resolved tracking, gated so a partial scan can never falsely
      resolve something it didn't actually re-check); and a REST API
      (account connect/list/scan-trigger, scan history, open findings,
      mean-time-to-remediate) with every account-scoped route re-checking
      org ownership so one org can't read or scan another's connected AWS
      account by guessing an ID.
      **Not done** (needs external account registrations only a human
      can create, same reasoning as the GitHub PAT slice above): the
      actual GitHub App OAuth/webhook flow, Slack alerting, and
      billing — tracked below, unchanged.
- [ ] GitHub App: OAuth installation + webhooks, so PR creation doesn't
      require each user to hold a personal access token (superseds the
      CLI+PAT slice above now that theknight-server exists to run it from)
- [ ] Slack alerting on new critical/high findings
- [ ] Pricing page + usage-based billing on monitored resource count

## V2 — expand surface area

- [ ] GCP scanner + rule mappings (second-most-common in ICP)
- [ ] Compliance report export (SOC 2-style PDF)
- [ ] Policy-as-code: customers write their own rules against the
      `scanner.Resource` / `rules.Rule` interfaces
- [ ] Azure scanner, if ICP demand supports it

## Explicitly out of scope for now

- Auto-applying fixes without human review (trust argument in the README
  depends on this staying a PR, not an auto-merge)
- Runtime/workload security (this is a config-posture tool, not an
  EDR/CSPM-runtime hybrid)
