# Roadmap

## MVP — AWS CLI scanner + remediation PR generator (4-6 weeks)

Goal: a real, runnable tool. This is the portfolio artifact.

- [x] `internal/scanner`: discovery for S3 buckets, IAM roles/policies, EC2
      security groups
- [ ] `internal/rules`: first rule set
  - [x] `s3-public-read` — public bucket ACL or policy, unless a Public
        Access Block configuration restricts it
  - [ ] `s3-public-write` — same signals, write permission (ACL/policy
        detection already captures `acl_public_write`; just needs a rule)
  - [x] `iam-wildcard-action` — `"Action": "*"` in an Allow statement,
        inline or attached managed policy
  - [ ] `iam-wildcard-resource` — `"Resource": "*"` (scanner already
        captures `has_wildcard_resource`; just needs a rule)
  - [x] `sg-open-ingress` — security group open to `0.0.0.0/0`/`::/0` on a
        sensitive port, or all ports via protocol `-1`
- [ ] Severity scoring that accounts for exposure (public-facing weighted
      above internal-only)
- [ ] `internal/remediate`: Terraform patch templates for the rules above,
      keyed by `RemediationID`
- [ ] `theknight remediate`: given a finding, render the Terraform diff and
      an explanation (no PR creation yet — local diff output is enough for
      MVP)
- [ ] table/JSON output polish, `--severity` filter flag
- [x] Tests against recorded/fixture AWS API responses (no live account
      needed to run CI) — fake `s3API`/`iamAPI`/`ec2API` implementations,
      20 tests covering discovery + rule evaluation
- [ ] README demo GIF or asciinema recording

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
