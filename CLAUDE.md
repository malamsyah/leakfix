# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository status

This repo is **pre-implementation**. Only `README.md`, `SPEC.md`, and `.gitignore` exist; there is no Go code, `go.mod`, or commit history yet. **`SPEC.md` is the source of truth** for v1 — read it before making any non-trivial change. The intended layout (Section 4) and generation order (Section 16) live there. When the user asks to "build X" or "implement Y", first locate the relevant section in `SPEC.md` and follow it; deviations need explicit justification.

## Non-negotiable design principles

These three principles (SPEC.md §1) shape every decision. Do not deviate without explicit justification in the PR description:

1. **Revoke first; history rewrite is opt-in.** The headline output is the revocation runbook. `git-filter-repo` is gated behind `--rewrite-history` with loud side-effect warnings.
2. **Wrap, don't reinvent.** Detection → Kingfisher. History rewrite → `git-filter-repo`. PR/issue creation → GitHub API. The tool's value is orchestration *above* these — never reimplement.
3. **Generate the action; don't execute the irreversible.** Reversible operations (open PR, draft issue, push feature branch) are automated. Irreversible ones (revoke a live key, force-push, delete refs) remain the human's job. There is no `--auto-yes`, `--force`, or auto-revoke flag, and there must never be one.

## Architecture flow

`leakfix remediate <repo>` runs six sequential stages (SPEC.md §6):

1. **SCAN** — subprocess `kingfisher scan --format json` (optionally `--access-map`); parse to `[]scanner.Finding`. Dedupe by `secret_hash` so the same secret across files becomes one `Finding` with multiple `Location`s (§9.6).
2. **PLAN** — single agent call per finding produces a complete `PlanItem` (provider classification + runbook lookup + minimal code edit). v0.3 merged the old triage/plan split.
3. **REDACT** — `Plan.Validate()` then `Plan.Redact()`. The redacted Plan is the only object permitted past this stage. Hard-error if any literal secret survives.
4. **PRESENT** — render via `internal/templates/plan.md.tmpl`. Stop here unless `--apply`.
5. **EXECUTE** (`--apply` only, reversible operations only) — idempotency check → branch → apply staged code edits → commit + push → open issue → open PR → update issue with PR number. With `--rewrite-history`, append the `git-filter-repo` command to the report; **do not** execute force-push.
6. **REPORT** — render via `internal/templates/report.md.tmpl`.

Stage 5 ordering matters: open issue **first** (PR body needs `IssueNumber`), then open PR, then update issue body with `PRNumber`.

## Critical implementation rules

From SPEC.md §10 ("What NOT to do") plus the bits most easily forgotten:

- **Redaction is the security boundary.** A literal secret value must never appear in the rendered Plan, PR body, issue body, commit message, or info-level logs. Debug-level logs may contain redacted previews only. The placeholder format (§8.2): `≤8 chars` → `[REDACTED]`; `>8 chars` → keep first 4 and last 4, e.g. `AKIAIOSFODNN7EXAMPLE` → `AKIA…[REDACTED]…MPLE`. Sort secrets by length descending before replacement to prevent partial-substring bugs.
- **Prefix-match Kingfisher rule IDs**, never exact-match (§7.3). Runbook lists `kingfisher.aws.access_key`; Kingfisher emits `kingfisher.aws.access_key.v2` → match. No-match falls back to `_generic.yaml`, never errors.
- **Embed, don't inline.** Runbook YAML lives in `internal/runbooks/data/` via `go:embed`. Markdown templates live in `internal/templates/` via `go:embed`. LLM prompts live as named constants in `internal/agent/prompts.go`, never inline at call sites.
- **`propose_code_edit` validates at agent-loop time** (§9.5): the tool reads the file and confirms the `find` string matches **exactly once** before staging. Zero matches or multiple matches → return error so the agent retries; do not defer the failure to Stage 5.
- **Branch name is deterministic** (§13.1): `leakfix/remediate-<short-hash>` where `<short-hash>` is `sha256(sorted(FindingIDs))[:8]`. Same findings → same branch → idempotent re-runs.
- **Dirty working tree refuses `--apply`** (§13.4). No `--allow-dirty` flag. Read-only commands (`scan`, dry-run `remediate`) work fine.
- **Sequential finding processing in v1.** No concurrency.
- **Anthropic only for the LLM.** No configurable provider in v1.
- **Env vars + flags only.** No `.leakfix.yaml` config file in v1.

## Tech stack & layout

Go 1.22+, `cobra`+`viper` (viper for env-var binding only — no config-file feature), Anthropic Go SDK (pin in `go.mod`), `go-git/go-git/v5` for local git, shell-out for `git-filter-repo`, `google/go-github`, `gopkg.in/yaml.v3`, stdlib `slog`, `stretchr/testify`. Apache 2.0 licensed.

File layout in SPEC.md §4. Notable points: `cmd/leakfix/main.go` is the CLI entrypoint; everything else is under `internal/` (scanner, agent, runbooks, git, github, plan, templates, report). Test fixtures live in `testdata/fixtures/`.

## Common commands (per SPEC.md §14, README, and the CI gate)

The Go module doesn't exist yet, but per spec:

```bash
go test ./...                     # unit tests
go test -tags=integration ./...   # integration tests (require kingfisher on PATH)
golangci-lint run                 # lint with config in .golangci.yml
go build -o bin/leakfix ./cmd/leakfix
leakfix doctor                    # verify kingfisher, git-filter-repo, gh, ANTHROPIC_API_KEY
leakfix scan .                    # self-scan; CI runs this as a release gate
```

Runtime env vars: `ANTHROPIC_API_KEY` (required), `GH_TOKEN` (or `gh` CLI auth), `LEAKFIX_MODEL`, `LEAKFIX_MAX_FINDINGS` (default 50), `LEAKFIX_LOG_LEVEL`.

## Agent loop guardrails

When implementing the Stage 2 agent loop (`internal/agent/`), enforce the hard limits in `internal/agent/guardrails.go` (§9.4):

| Limit | Default |
|---|---|
| Iterations per finding | 8 |
| Input tokens per finding | 20,000 |
| Output tokens per finding | 4,000 |
| Total findings per run | 50 (`LEAKFIX_MAX_FINDINGS`) |
| Per-finding timeout | 90s |
| Total run timeout | 15min |
| Max `read_file` bytes | 50KB |

On iteration/token/timeout exhaustion: record partial result with `agent_rationale = "agent loop exceeded <limit>; falling back to runbook defaults"` and continue to the next finding. On total-findings exhaustion: error before the loop starts.

The Anthropic client lives behind `internal/agent/client.go` `Client` interface so `mockClient` can drive deterministic tests (§14.2). `read_file` is sandboxed to the target repo via `filepath.Rel` + prefix check; symlinks escaping the repo are rejected (§9.7).

## Acceptance criteria

SPEC.md §15 lists the v1 done-bar. Notable items: `Plan.Validate()` + `Plan.Redact()` reject any plan containing the literal secret post-redaction; idempotent re-runs don't create duplicate PRs; `--rewrite-history` emits the command but does not force-push; CI runs `leakfix scan .` against itself before release; test fixtures use clearly-fake secret patterns only.
