# Roadmap

## MVP — AWS CLI scanner + remediation PR generator (4-6 weeks)

Goal: a real, runnable tool. This is the portfolio artifact.

- [ ] `internal/scanner`: discovery for S3 buckets, IAM roles/policies, EC2
      security groups
- [ ] `internal/rules`: first rule set
  - [ ] `s3-public-read` / `s3-public-write` — public bucket ACL or policy
  - [ ] `iam-wildcard-action` / `iam-wildcard-resource` — `"Action": "*"` or
        `"Resource": "*"` in an attached policy
  - [ ] `sg-open-ingress` — security group open to `0.0.0.0/0` on a
        sensitive port (22, 3389, databases)
- [ ] Severity scoring that accounts for exposure (public-facing weighted
      above internal-only)
- [ ] `internal/remediate`: Terraform patch templates for the rules above,
      keyed by `RemediationID`
- [ ] `theknight remediate`: given a finding, render the Terraform diff and
      an explanation (no PR creation yet — local diff output is enough for
      MVP)
- [ ] table/JSON output polish, `--severity` filter flag
- [ ] Tests against recorded/fixture AWS API responses (no live account
      needed to run CI)
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
