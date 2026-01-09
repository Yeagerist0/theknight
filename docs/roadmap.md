# Roadmap

## MVP — AWS CLI scanner + remediation PR generator (4-6 weeks)

Goal: a real, runnable tool. This is the portfolio artifact.

- [x] `internal/scanner`: discovery for S3 buckets, IAM roles/policies, EC2
      security groups
- [x] `internal/rules`: first rule set
  - [x] `s3-public-read` — public bucket ACL or policy, unless a Public
        Access Block configuration restricts it
  - [x] `s3-public-write` — ACL-only signal (a public bucket *policy*
        doesn't tell us read vs. write without parsing the policy
        document, which the S3 scanner doesn't do yet — see note below)
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
- [ ] table/JSON output polish, `--severity` filter flag
- [x] Tests against recorded/fixture AWS API responses (no live account
      needed to run CI) — fake `s3API`/`iamAPI`/`ec2API` implementations,
      42 test cases covering discovery, rule evaluation, and remediation
- [x] Integration tests against real AWS API wiring (not just fakes) —
      `internal/scanner/integration_test.go` (`//go:build integration`)
      provisions real S3/IAM/EC2 resources against LocalStack and runs the
      actual discovery functions. `make integration-test` / CI can run
      this as a slower, Docker-gated tier alongside the fast fixture tests
- [ ] README demo GIF or asciinema recording
- [ ] S3 bucket policy document parsing (mirror what IAM discovery already
      does) so `s3-public-write` can also fire on policy-granted write
      access, not just ACL grants

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
