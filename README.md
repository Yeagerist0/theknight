# TheKnight

Cloud misconfiguration scanner for AWS that doesn't just report — it opens
the pull request that fixes it.

```
$ theknight scan --profile prod --region us-east-1
SEVERITY   RULE              RESOURCE                TITLE
critical   s3-public-read    my-app-uploads          S3 bucket allows public read
high       iam-wildcard      deploy-role             IAM role grants Action: "*"
high       sg-open-ingress   sg-0a1b2c3d             Security group open to 0.0.0.0/0 on 22
```

## What it does

TheKnight scans an AWS account for the misconfigurations that cause most
breaches — public S3 buckets, over-permissioned IAM roles, security groups
open to the world — and ranks them so a small team can act on the ones that
matter instead of triaging a 400-line report.

The detection engine (this repo) is open source. The idea is that a fix
shouldn't require logging into another dashboard: point TheKnight at a
Terraform-managed AWS account and it proposes the patch as a PR against
the infra repo, reviewed and merged like any other change.

## Status

Early scaffold. `theknight scan` and `theknight remediate` exist as CLI
commands with the plumbing in place (AWS auth, resource discovery, a rule
registry, table/JSON output); the actual detection rules and the
Terraform-patch generator are not written yet. See
[docs/roadmap.md](docs/roadmap.md) for the build sequence.

## Usage

```
go build -o theknight ./cmd/theknight
./theknight scan --profile <aws-profile> --region us-east-1
```

Auth follows the standard AWS SDK credential chain (env vars, shared config
profile via `--profile`, instance role, etc).

## Architecture

```
cmd/theknight/        CLI entrypoint (cobra)
internal/awsclient/   AWS SDK config/session resolution
internal/scanner/     Resource discovery, normalized into scanner.Resource
internal/rules/       Rule interface + registry; Evaluate() runs rules over resources
internal/remediate/   Finding -> Terraform fix template mapping (not yet implemented)
internal/report/      table/json output
configs/rules/        Rule definitions (data-driven checks, once rules exist)
```

`scanner.Resource` is a normalized, provider-agnostic type — rules operate
on it rather than raw AWS SDK structs, so a GCP or Azure scanner can plug
into the same rule engine later without rewriting detection logic.

---

## If this were a startup

### The problem

Cloud misconfigurations are consistently one of the top causes of breaches
(public S3 buckets, over-permissioned IAM roles, open security groups).
Existing tools either dump a wall of findings with no prioritization a
human can act on (AWS Config, Prowler, ScoutSuite), are expensive
enterprise platforms only large companies can justify ($50k+/yr — Wiz,
Orca), or detect but don't fix, handing remediation back to an
already-underwater platform team.

The gap: engineering teams of 10–200 with a real cloud footprint, no
dedicated security team, and no budget for Wiz/Orca. They know they're
exposed but don't have the headcount to triage 400 findings a week.

### The wedge

Don't compete with Wiz on "comprehensive cloud security platform" — that's
crowded and well-funded. Compete on one narrow, sharp promise: **we find
the misconfigurations that actually matter, and we send you a pull request
that fixes them.** Detection-to-remediation in one PR, not a dashboard you
have to log into. Most competitors sell visibility; this sells time saved
— an engineer merges a PR instead of spending an afternoon in a security
dashboard. Shipping the fix into the workflow the customer already lives
in (GitHub) rather than adding another tool to check is the differentiated
distribution mechanism.

### ICP

Series A–C startups, 10–200 engineers, primarily AWS, Terraform-managed
infra (this matters — it's what makes a remediation PR tractable to
generate), no dedicated security hire but a security-conscious eng lead or
CTO who knows they're exposed. Findable in bulk via Crunchbase + "uses
Terraform" job postings.

### Business model

- **Open-core**: CLI scanner + rule engine open source — drives adoption,
  credibility, and inbound.
- **Paid layer**: hosted scheduled scans, the remediation-PR bot, Slack
  alerts, historical trend reporting (the "are we more or less secure this
  month" report a CTO shows their board).
- **Pricing**: usage-based on monitored resource count, matching value
  delivered and avoiding the enterprise sales cycle that kills most
  security startups at seed.
- **Land-and-expand**: free scanner to paid once the PR bot merges its
  first fix — that's the product-qualified-lead signal.

### Moat

- **Remediation corpus** — accumulated "finding pattern → verified-safe
  Terraform fix" mappings across real customer infra, compounding over
  time.
- **Workflow lock-in via GitHub** — once CI is wired to the PR bot,
  switching cost is real, unlike churning off a dashboard.
- **Trust** — security tooling is a trust business. Open-source detection
  plus never auto-applying changes (always PR, human-reviewed) is both an
  ethical stance and the reason a wary CTO lets you near their AWS account.

### MVP → V1 → V2

- **MVP** (this repo, 4–6 weeks): AWS-only CLI scanner + risk engine +
  remediation PR generator.
- **V1**: hosted scheduled scanning, Slack/GitHub integration, pricing
  page — a 2–3 month build on top of the MVP.
- **V2**: multi-cloud (GCP next), compliance report exports for SOC 2
  auditors, policy-as-code layer for customer-authored rules.

See [docs/roadmap.md](docs/roadmap.md) for the detailed build sequence.
