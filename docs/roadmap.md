# Roadmap

## MVP — AWS CLI scanner + remediation PR generator (4-6 weeks)

Goal: a real, runnable tool. This is the portfolio artifact.

**MVP complete as of 2026-07-17.** Everything below is done, unit +
integration tested (LocalStack), and pushed. What's left for this repo is
V1/V2, not MVP polish.

- [x] `internal/scanner`: discovery for S3 buckets, IAM roles/policies, EC2
      security groups
- [x] `internal/rules`: first rule set
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
      explanation for every finding with a registered template (no PR
      creation yet — stdout output is enough for MVP)
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
      `internal/scanner/integration_test.go` (`//go:build integration`)
      provisions real S3/IAM/EC2 resources against LocalStack and runs the
      actual discovery functions. `make integration-test` / CI can run
      this as a slower, Docker-gated tier alongside the fast fixture tests
- [x] README demo GIF (`docs/assets/demo.gif`) — recorded with
      asciinema + agg against the actual compiled binary pointed at
      LocalStack via `AWS_ENDPOINT_URL` (works with zero code changes for
      IAM/EC2; S3 needs path-style addressing LocalStack requires on
      localhost, which the production S3 client intentionally doesn't set
      — see the `s3.NewFromConfig` comment in `internal/awsclient` — so
      the recording demos IAM + EC2 only, not S3)
- [x] S3 bucket policy document parsing — `bucketPolicyPermissions` in
      `internal/scanner/s3.go`, mirroring the IAM policy parsing pattern.
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

- [ ] Scheduled scanning (cron-style, per connected AWS account)
- [ ] GitHub App: opens the remediation PR directly against the customer's
      infra repo instead of printing a local diff
- [ ] Slack alerting on new critical/high findings
- [ ] Historical trend report (findings over time, mean time-to-remediate)
- [ ] Pricing page + usage-based billing on monitored resource count
- [ ] Multi-account support (org-level, not just single profile)

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
