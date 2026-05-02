# Architecture

Six sequential stages, kept simple by design. The full spec is in
[`/SPEC.md`](../SPEC.md); this doc summarises the moving parts and explains a
few decisions that aren't visible in the code.

## Pipeline

```
SCAN → PLAN → REDACT → PRESENT → EXECUTE → REPORT
```

| Stage | Package | Responsibility |
|---|---|---|
| SCAN | `internal/scanner` | Subprocess `kingfisher`, parse JSON, dedupe by `secret_hash`. |
| PLAN | `internal/agent` | Per-finding LLM loop. Tools: `list_providers`, `lookup_runbook`, `read_file`, `assess_finding`, `propose_code_edit`, `finalize_plan_item`. |
| REDACT | `internal/plan` | `Validate()` then `Redact()`. The redacted plan is the only object permitted past this stage. |
| PRESENT | `internal/render` | `text/template` rendering using bundled `*.md.tmpl` files. |
| EXECUTE | `internal/git`, `internal/githubclient` | (`--apply` only) idempotency check, branch + commit + push, issue → PR → update issue. |
| REPORT | `internal/report` | Final markdown summary including any `ExecutionFailure`s. |

## Why a Client interface for Anthropic?

`agent.Client` is a tiny interface (one `Complete` method). The live
implementation lives in `agent/client.go` and depends on the official Anthropic
Go SDK; tests never import it. Tests use a `scriptedClient` in `agent/mock_test.go`
that returns canned tool-use sequences.

This keeps the agent loop unit-testable without ever talking to the network.

## Stage 5 ordering

Open issue → open PR → update issue body. The PR body needs `IssueNumber`, the
issue body wants the final `PRNumber`. The order is captured in
`internal/cli/apply.go::executeApply`.

## Redaction is the security boundary

Three layers:

1. `internal/plan/plan.go::Redact` walks every string field in the plan and
   replaces every known secret with a placeholder (SPEC §8.2). If any literal
   survives the pass, `Redact` returns an error and the run aborts.
2. The placeholder algorithm downgrades any prefix-preserving placeholder
   (`first4…[REDACTED]…last4`) to plain `[REDACTED]` if it would expose a
   shorter secret as a substring.
3. Templates have a `redact` helper for defense-in-depth; it's a no-op in
   normal flow, since the plan is already redacted.

## The agent's `propose_code_edit` validation

When the agent proposes an edit, the tool reads the file and counts
occurrences of `find` (SPEC §9.5):

- 0 → error, agent retries with a different find string
- 1 → stage the edit, return `{ok: true}`
- 2+ → error, agent retries with more context

This shifts the failure-mode surface from Stage 5 (apply-time) into the agent
loop, where retries cost only LLM tokens, not partial PRs.

## Idempotency

Branch names are deterministic: `leakfix/remediate-<sha256(sorted FindingIDs)[:8]>`.
A re-run with the same findings produces the same branch name; if a PR is
already open against that branch, the run exits cleanly with a message instead
of opening a duplicate.

## What isn't here

- No telemetry. No `/version-check` ping. No analytics endpoint.
- No `--auto-yes`, `--force`, `--allow-dirty`. By design.
- No history-rewrite execution. `--rewrite-history` emits the
  `git-filter-repo` invocation and side-effect list; force-pushing remains a
  human decision.

## Running E2E tests

End-to-end tests against a live API key (Anthropic + GitHub) are documented
inline in test files but are **not** part of CI. Run them manually before
tagging a release:

```bash
ANTHROPIC_API_KEY=... GH_TOKEN=... go test -tags=integration,live ./...
```

## Self-scan release gate

`go test -tags=selfscan ./...` (or the equivalent CI step) runs `leakfix scan .`
against the leakfix repo itself before any tag. If anything is found, the
release is blocked.
