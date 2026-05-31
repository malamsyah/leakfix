# `leakfix`

> Remediation agent for [Kingfisher](https://github.com/mongodb/kingfisher) findings. Generates per-provider revocation runbooks, opens review-ready PRs, and (optionally) scrubs git history — with side effects spelled out, not hidden.

[![CI](https://github.com/malamsyah/leakfix/actions/workflows/ci.yml/badge.svg)](https://github.com/malamsyah/leakfix/actions/workflows/ci.yml)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Go Reference](https://pkg.go.dev/badge/github.com/malamsyah/leakfix.svg)](https://pkg.go.dev/github.com/malamsyah/leakfix)

> **Status:** alpha. Works on a single repo. GitHub-only. Six providers bundled.
> Built in the open. Use against forks before pointing it at anything important.

## Overview

https://storage.googleapis.com/mindgraph-public-assets/leakfix_full.mp4

<video src="https://storage.googleapis.com/mindgraph-public-assets/leakfix_full.mp4" controls width="100%"></video>

---

## Why this exists

There are excellent secret *scanners*. There are very few good secret *remediation* tools.

The default tutorial when you leak a key leads with `git filter-repo`, as if rewriting history is the goal. It isn't. [GitHub's own guidance](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository) is clear: **revoke first, rewriting history is often unnecessary, and rewriting has serious side effects** — commit SHAs change, GPG signatures get dropped, open PR diffs invalidate, and any collaborator with an old clone can re-contaminate the repo on their next push.

`leakfix` is opinionated about this:

1. **Revocation is the headline action.** The tool generates a per-provider runbook with the exact steps and console URLs to revoke and rotate the leaked credential.
2. **History rewrite is opt-in.** Hidden behind `--rewrite-history`, with the side effects listed loudly in the output.
3. **Irreversible operations are never automated.** `leakfix` will open the PR for you. It will not call AWS to revoke your key, and it will not force-push your repo. Those remain the human's job.

---

## What it actually does

```bash
$ leakfix remediate ./my-repo
```

Outputs a markdown plan like:

```markdown
# Remediation plan for ./my-repo

## Findings: 2

### 1. AWS IAM Access Key — `internal/config/dev.go:42`
**Severity:** critical (validated; access map shows `iam:*`, `s3:*` on prod account)

**Revocation steps:**
1. Identify the IAM user (access map: `deploy-bot@prod`)
2. Create a replacement key in the IAM console
3. Update consumers: GitHub Actions secret `AWS_ACCESS_KEY_ID`, deploy.yaml
4. Run: `aws iam delete-access-key --access-key-id AKIA... --user-name deploy-bot`
5. Audit CloudTrail for unauthorized usage since 2026-04-12

**Proposed code change:** replace literal value with `os.Getenv("AWS_ACCESS_KEY_ID")`

### 2. GitHub Personal Access Token — `scripts/release.sh:8`
...
```

With `--apply`, it creates a branch, commits the env-var refactor, opens a PR with the runbook in the body, and opens a tracking issue with the revocation checklist.

---

## Quickstart

### Install

```bash
# From source
git clone https://github.com/malamsyah/leakfix
cd leakfix
make setup     # installs kingfisher, git-filter-repo, gh (best-effort, see SETUP.md)
make build     # produces ./bin/leakfix
./bin/leakfix doctor

# Once published:
brew install malamsyah/tap/leakfix
go install github.com/malamsyah/leakfix/cmd/leakfix@latest
```

For the full per-platform setup walk-through, see [`SETUP.md`](SETUP.md).

### Prerequisites

```bash
leakfix doctor
```

This verifies the four things `leakfix` shells out to:

- [Kingfisher](https://github.com/mongodb/kingfisher) on `$PATH`
- [`git-filter-repo`](https://github.com/newren/git-filter-repo) on `$PATH` (only needed for `--rewrite-history`)
- [`gh`](https://cli.github.com/) CLI (for GitHub auth) **or** `GH_TOKEN` env var
- `ANTHROPIC_API_KEY` env var

`make setup` automates all four where it can; manual fallbacks are documented
in [`SETUP.md`](SETUP.md).

### Scan only

```bash
# Local repo
leakfix scan ./my-repo

# Remote single repo (clones via kingfisher)
leakfix scan github.com/owner/repo

# Every repo in a GitHub organization (or --user for a personal account)
leakfix scan-org acme-corp --limit 25
leakfix scan-org acme-corp --list-only      # see what would be scanned
```

Remote modes need `gh auth login` or `GH_TOKEN`/`GITHUB_TOKEN`/`KF_GITHUB_TOKEN`
in the env. Findings include direct GitHub commit/blob links so reviewers can
click straight to the leaked line. Vendored paths (`vendor/`, `node_modules/`,
…), test fixtures, and obvious dummy/example credentials are filtered out by
default — pass `--no-filter` to keep them.

### Dry-run remediation plan

```bash
leakfix remediate ./my-repo
```

This is the safe default. Outputs the plan to stdout, makes no changes.

### Apply (creates a real PR)

```bash
leakfix remediate ./my-repo --apply
```

### With history rewrite plan

```bash
leakfix remediate ./my-repo --apply --rewrite-history
```

This adds the `git-filter-repo` invocation to the report. **It does not run it.** Force-pushing the rewritten history is on you, intentionally.

---

## How it works

```
   kingfisher scan        →    Claude agent          →    git + GitHub
   (find + validate +          (triage, runbook            (branch, commit,
    map blast radius)           lookup, plan)               PR, issue)
```

Three things, in sequence:

1. **Detection layer** — Kingfisher finds candidate secrets, validates which are still live, and (with `--access-map`) maps each credential's blast radius (which IAM user, what permissions, what resources).
2. **Reasoning layer** — A Claude agent classifies each finding by provider, looks up the bundled runbook for that provider, and drafts a per-finding remediation plan including a minimal code change.
3. **Execution layer** — `leakfix` opens the branch, commit, and PR. Anything irreversible (revoking keys, force-pushing) it leaves for the human.

The split is deliberate. Reversible operations get automated. Irreversible ones don't.

---

## Provider support (v1)

Bundled runbooks:

- AWS IAM Access Key
- GitHub Personal Access Token (classic and fine-grained)
- Stripe API key
- Slack webhook URL
- OpenAI API key
- Anthropic API key

Findings for any other Kingfisher-detected provider get a generic fallback runbook with a TODO pointing to a contribution issue. Adding a provider is a YAML-only change — see [`docs/PROVIDERS.md`](docs/PROVIDERS.md).

---

## Configuration

`leakfix` is intentionally configured by environment variables and flags. No config file in v1.

| Variable | Purpose | Required |
|---|---|---|
| `ANTHROPIC_API_KEY` | API key for the Claude agent | yes |
| `GH_TOKEN` | GitHub auth (if `gh` CLI not present) | one of these two |
| `LEAKFIX_MODEL` | Override Claude model (default: latest Sonnet) | no |
| `LEAKFIX_MAX_FINDINGS` | Cap findings per run (default: 50) | no |
| `LEAKFIX_LOG_LEVEL` | `debug` / `info` / `warn` / `error` (default: info) | no |

`leakfix` does not collect telemetry. There is no analytics endpoint. The only network calls are to: Kingfisher's validators (which you control), the Anthropic API, and the GitHub API.

---

## Design philosophy

Three principles. They shape every decision in this codebase. If you're contributing, internalise them first.

1. **Revoke first. History rewrite is opt-in.**
2. **Wrap, don't reinvent.** Detection lives in Kingfisher. History rewriting lives in `git-filter-repo`. PR creation lives in the GitHub API. `leakfix` is the orchestration layer above them.
3. **Generate the action; don't execute the irreversible.** Reversible operations are automated; irreversible ones (revoke a live key, force-push) require an explicit human step.

See [`docs/DESIGN_PHILOSOPHY.md`](docs/DESIGN_PHILOSOPHY.md) for the long version.

---

## FAQ

**Why not just use GitGuardian / TruffleHog Enterprise / [vendor]?**
Use them if they fit. `leakfix` is open-source, CLI-only, runs entirely on your machine, and centres revocation in a way most commercial tools don't. It's also free and you can read every line.

**Why Kingfisher and not Gitleaks/TruffleHog?**
Kingfisher is the most modern OSS scanner, has live validation under Apache 2.0, and uniquely produces an `--access-map` that lets the agent reason about blast radius. Gitleaks/TruffleHog ingestion is on the roadmap (`v0.2`) so you can use whichever scanner you prefer later.

**Will this auto-revoke my keys?**
No. By design. Revocation is irreversible and provider-specific; the tool generates the exact command and console URL but you pull the trigger.

**Will this force-push my repo?**
Also no. With `--rewrite-history` it generates the `git-filter-repo` invocation and lists the side effects, but force-push is your call.

**Does it work on private repos?**
Yes, as long as `gh auth status` shows you authenticated or `GH_TOKEN` is set with `repo` scope.

**Does it work on GitLab / Bitbucket / self-hosted Git?**
Not in v1. GitHub-only. On the roadmap.

**Why Apache 2.0 and not MIT?**
Patent grant. Friendlier for downstream commercial use than AGPL (TruffleHog), more protective than MIT for a security tool.

---

## Contributing

PRs welcome, especially:

- New provider runbooks (YAML-only changes — see [`docs/PROVIDERS.md`](docs/PROVIDERS.md))
- Bug reports with a minimal reproducing fixture
- Documentation improvements

PRs that add features beyond the v1 scope (multi-repo, web UI, additional scanners, auto-revoke) will be politely closed and added to `ROADMAP.md`. The scope is deliberate.

Before opening a PR, please run:

```bash
go test ./...
golangci-lint run
leakfix scan .   # eat your own dog food
```

---

## Acknowledgments

- [Kingfisher](https://github.com/mongodb/kingfisher) by MongoDB — the detection + validation + blast-radius layer this entire tool sits on top of.
- [`git-filter-repo`](https://github.com/newren/git-filter-repo) by Elijah Newren — the history rewrite engine.
- The [Anthropic Claude](https://www.anthropic.com/) team for the agent SDK and the model.

---

## License

Apache 2.0. See [`LICENSE`](LICENSE).