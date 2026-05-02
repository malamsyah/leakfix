# `leakfix` — Tech Spec

> Spec version: **v0.3** (refined again)
> Project name: **leakfix** (locked)

## Changelog from v0.2

- **Simplified** Stages 2+3 into a single `PLAN` stage (Section 6, 9). The split was over-engineered; one agent call can produce the Plan directly.
- **Added** redaction algorithm with concrete placeholder format (Section 8.2).
- **Added** template render context spec — what data flows into each template, including post-creation values like PR/issue numbers (Section 11.0).
- **Added** template helper function registry (Section 11.4).
- **Added** operational behaviors section: branch naming, commit messages, idempotency, dirty working tree (Section 13).
- **Added** code-edit-application failure handling (Section 12).
- **Added** multiple-findings-of-same-secret resolution rule (Section 9.6).
- **Added** Kingfisher version pinning policy (Section 17.2).
- **Added** `leakfix doctor` and `leakfix runbook` output format specs (Section 5.2).
- **Added** `golangci-lint` config sketch (Section 14.6).

---

## 1. Read this section first — design philosophy

Three principles. Non-negotiable for v1. Deviate only with explicit justification in the PR description.

### 1.1 Revoke first. History rewrite is opt-in.

GitHub's own guidance: if a leaked credential can be revoked, that often *is* the fix. Rewriting history has serious side effects — commit SHAs change, GPG/SSH signatures are dropped, open PR diffs invalidate, and any collaborator who pushes their old clone re-contaminates the repo. The tool's primary output is the **revocation runbook**. History rewrite is gated behind an explicit `--rewrite-history` flag and accompanied by loud warnings.

### 1.2 Wrap, don't reinvent.

- Detection rules → Kingfisher
- History rewriting → `git-filter-repo`
- PR/issue creation → GitHub API

The tool's value is the orchestration *above* these. Resist any impulse to write custom detection rules or a custom history-rewrite engine.

### 1.3 Generate the action; don't execute the irreversible.

The agent produces revocation commands and provider console URLs but does NOT call provider APIs to revoke keys. It outputs the exact `git-filter-repo` invocation but does NOT force-push. Reversible operations (open a PR, draft an issue, push a feature branch) are automated; irreversible ones (revoke a live key, force-push history, delete refs) remain the human's responsibility.

---

## 2. Scope

### 2.1 In scope (v1)

- CLI commands: `scan`, `remediate`, `runbook`, `doctor`
- Single-repo operation only
- Kingfisher integration via subprocess; consume its JSON output including `--access-map` data
- Claude-API-driven agent for plan generation
- 6 bundled provider runbooks: AWS IAM, GitHub PAT, Stripe, Slack webhook, OpenAI, Anthropic
- Generic fallback runbook for unknown providers
- Reversible remediation: branch + commit + PR + tracking issue
- Dry-run mode (default) and `--apply` mode
- Optional `--rewrite-history` that emits the `git-filter-repo` command but does not execute force-push
- `--verbose` and `--quiet` logging flags
- Idempotent re-runs (Section 13.3)

### 2.2 Explicitly out of scope (v1)

| Feature | Reason |
|---|---|
| Multi-repo / org scanning | Scope creep; defer |
| Web UI, TUI, or interactive prompts | CLI is the entire surface area |
| Gitleaks / TruffleHog ingestion | Kingfisher-only in v1; cross-tool dedup is v0.2 |
| Auto-revoke via provider APIs | Irreversible; human-in-the-loop |
| Auto force-push after history rewrite | Irreversible; human-in-the-loop |
| Custom detection rules | We do not compete with rule libraries |
| Slack / Jira integrations | Defer |
| GitLab / Bitbucket | GitHub-only in v1 |
| Configurable LLM providers | Anthropic only |
| Config file (`.leakfix.yaml`) | Env vars + flags only in v1 |
| Concurrent finding processing | Sequential in v1; cost & complexity |
| Telemetry / analytics | Never |

If a feature feels like it belongs later, add it to `ROADMAP.md` and stop.

---

## 3. Tech stack

| Layer | Choice | Notes |
|---|---|---|
| Language | Go 1.22+ | |
| CLI framework | `spf13/cobra` + `spf13/viper` | viper for env-var binding only, no config-file feature |
| LLM | Anthropic API via official Go SDK | Pin to a specific version in `go.mod`; verify latest at generation time |
| Scanner | Kingfisher (Rust binary) | Required on PATH; `doctor` checks |
| Local git ops | `go-git/go-git/v5` | |
| History rewrite | shell out to `git-filter-repo` | |
| GitHub API | `google/go-github` | |
| YAML | `gopkg.in/yaml.v3` | |
| Logging | stdlib `slog` | Structured |
| Testing | stdlib `testing` + `stretchr/testify` | |
| License | Apache 2.0 | |

---

## 4. File layout

```
leakfix/
├── cmd/leakfix/
│   └── main.go
├── internal/
│   ├── scanner/
│   │   ├── kingfisher.go        # subprocess wrapper, JSON parser
│   │   ├── version.go           # supported Kingfisher version range check
│   │   └── types.go             # Finding, AccessMap, Validation structs
│   ├── agent/
│   │   ├── agent.go             # orchestration loop
│   │   ├── tools.go             # tool definitions for the LLM
│   │   ├── prompts.go           # system prompts as Go string constants
│   │   ├── client.go            # Anthropic client interface (for mocking)
│   │   └── guardrails.go        # iteration/token/timeout limits
│   ├── runbooks/
│   │   ├── runbooks.go          # loader + registry + rule matcher
│   │   └── data/                # YAML files, embedded via go:embed
│   │       ├── _generic.yaml    # fallback for unknown providers
│   │       ├── aws_iam.yaml
│   │       ├── github_pat.yaml
│   │       ├── stripe.yaml
│   │       ├── slack_webhook.yaml
│   │       ├── openai.yaml
│   │       └── anthropic.yaml
│   ├── git/
│   │   ├── operations.go        # branch, commit, push (go-git)
│   │   ├── conventions.go       # branch naming, commit message templates
│   │   └── filterrepo.go        # filter-repo command builder + executor
│   ├── github/
│   │   ├── client.go            # auth from gh CLI or GH_TOKEN
│   │   ├── pr.go
│   │   └── issue.go
│   ├── plan/
│   │   ├── plan.go              # Plan struct + Validate()
│   │   ├── redact.go            # redaction algorithm (Section 8.2)
│   │   └── render.go            # markdown rendering using templates/
│   ├── templates/
│   │   ├── plan.md.tmpl         # dry-run markdown plan
│   │   ├── pr_body.md.tmpl      # PR body
│   │   ├── issue_body.md.tmpl   # tracking issue body
│   │   ├── report.md.tmpl       # final post-execution report
│   │   └── helpers.go           # template func map (Section 11.4)
│   └── report/
│       └── report.go            # post-execution summary writer
├── testdata/
│   └── fixtures/
│       ├── aws-leak/
│       ├── github-pat-leak/
│       └── multi-leak/
├── docs/
│   ├── ARCHITECTURE.md
│   ├── PROVIDERS.md             # how to add a runbook
│   └── DESIGN_PHILOSOPHY.md
├── .github/workflows/
│   ├── ci.yml
│   └── release.yml
├── .golangci.yml
├── go.mod
├── go.sum
├── README.md
├── LICENSE
├── ROADMAP.md
└── .goreleaser.yaml
```

---

## 5. CLI surface

```
leakfix scan <repo-path> [flags]
  --access-map              Run Kingfisher with --access-map (slower; needs cloud creds)
  --format <md|json|sarif>  Output format (default: md)
  --output <file>           Write to file instead of stdout
  --confidence <low|med|hi> Kingfisher confidence threshold (default: medium)

leakfix remediate <repo-path> [flags]
  --apply                   Create branch, commits, PR (default: dry-run)
  --rewrite-history         Additionally emit git-filter-repo plan + warnings
  --providers <list>        Comma-separated; restrict to these providers
  --confidence <low|med|hi>
  --base-branch <name>      Base branch for the PR (default: repo default branch)
  --no-issue                Skip tracking issue creation
  --output <file>           Also write plan/report to file

leakfix runbook <provider>           Print one runbook YAML
leakfix runbook --list                List bundled providers (table format)
leakfix runbook --list --format json  Machine-readable list

leakfix doctor              Verify kingfisher, git-filter-repo, gh, ANTHROPIC_API_KEY
leakfix doctor --format json   Machine-readable diagnostic output

# Global flags
  --verbose, -v             Increase log verbosity (debug)
  --quiet, -q               Suppress non-error output
  --no-color                Disable ANSI color
```

There is no `--auto-yes`, `--force`, or equivalent. Do not add one.

### 5.1 Configuration

Configured by env vars and flags only. **No config file in v1.**

| Var | Purpose | Required |
|---|---|---|
| `ANTHROPIC_API_KEY` | Claude API key | yes |
| `GH_TOKEN` | GitHub auth (fallback if `gh` CLI not present) | one of these two |
| `LEAKFIX_MODEL` | Override Claude model | no |
| `LEAKFIX_MAX_FINDINGS` | Cap findings per run (default: 50) | no |
| `LEAKFIX_LOG_LEVEL` | `debug`/`info`/`warn`/`error` (default: info) | no |

GitHub auth precedence: `gh` CLI auth first, then `GH_TOKEN`, then error.

### 5.2 Output formats for `doctor` and `runbook`

#### `leakfix doctor` (default human format)

```
✓ kingfisher 0.6.2          (>= 0.6.0 supported)
✓ git-filter-repo 2.45.0    (>= 2.40.0 supported)
✓ gh CLI 2.55.0 — authenticated as malamsyah
✓ ANTHROPIC_API_KEY         set (sk-ant-...3F2x)
✓ Go 1.22.5                 (>= 1.22 supported)

All checks passed.
```

On failure, exit code 1 with `✗` markers and one-line remediation hints (e.g., `install with: pip install git-filter-repo`).

#### `leakfix doctor --format json`

```json
{
  "ok": false,
  "checks": [
    {"name": "kingfisher", "ok": true, "version": "0.6.2", "supported_range": ">=0.6.0"},
    {"name": "git_filter_repo", "ok": false, "error": "not found on PATH",
     "remediation": "install with: pip install git-filter-repo"},
    ...
  ]
}
```

#### `leakfix runbook --list` (default table format)

```
ID                       DISPLAY NAME                  RULES
aws_iam_access_key       AWS IAM Access Key            kingfisher.aws.access_key
github_pat               GitHub Personal Access Token  kingfisher.github.pat_classic, ...
...
_generic                 Unknown / Unsupported         (fallback)
```

#### `leakfix runbook <id>` — prints raw YAML to stdout.

---

## 6. Architecture flow

```
   leakfix remediate <repo>
            │
            ▼
   ┌─────────────────────┐
   │ Stage 1: SCAN       │  Subprocess: kingfisher scan --format json [--access-map]
   │                     │  Parse stdout → []scanner.Finding
   └──────────┬──────────┘
              ▼
   ┌─────────────────────┐
   │ Stage 2: PLAN       │  Agent: for each finding, classify provider + lookup runbook
   │                     │  + propose code edit, all in one tool-use loop.
   │                     │  Output: Plan
   └──────────┬──────────┘
              ▼
   ┌─────────────────────┐
   │ Stage 3: REDACT     │  plan.Validate() + redact literals via plan.Redact()
   │                     │  Hard error if literal secret present post-redaction
   └──────────┬──────────┘
              ▼
   ┌─────────────────────┐
   │ Stage 4: PRESENT    │  Render Plan via templates/plan.md.tmpl → stdout/file
   │                     │  If --apply: continue; else: stop here
   └──────────┬──────────┘
              ▼ (--apply)
   ┌─────────────────────┐
   │ Stage 5: EXECUTE    │  Reversible only:
   │                     │   - Idempotency check (Section 13.3)
   │                     │   - Create branch (Section 13.1)
   │                     │   - Apply staged code edits (Section 12.4 on failure)
   │                     │   - Commit (Section 13.2) + push
   │                     │   - Open PR (templates/pr_body.md.tmpl)
   │                     │   - Open tracking issue (templates/issue_body.md.tmpl)
   │                     │  If --rewrite-history:
   │                     │   - Append filter-repo command + warnings to report
   │                     │   - DO NOT execute force-push
   └──────────┬──────────┘
              ▼
   ┌─────────────────────┐
   │ Stage 6: REPORT     │  Render via templates/report.md.tmpl
   └─────────────────────┘
```

**Note:** v0.2 had Stages 2 and 3 as separate triage / plan steps. v0.3 merges them into a single `PLAN` stage — one agent call per finding produces the full PlanItem directly. The split was artificial.

---

## 7. Runbook schema

### 7.1 Standard runbook

YAML in `internal/runbooks/data/`, embedded via `go:embed`.

```yaml
id: aws_iam_access_key
display_name: AWS IAM Access Key
kingfisher_rules:
  - kingfisher.aws.access_key
severity_default: critical
revocation:
  console_url: https://console.aws.amazon.com/iam/home#/users
  api_command: |
    aws iam delete-access-key \
      --access-key-id <ACCESS_KEY_ID> \
      --user-name <USERNAME>
  steps:
    - "Identify the IAM user that owns this key (use STS GetCallerIdentity if access_map is empty)"
    - "Generate a replacement key via the IAM console or `aws iam create-access-key`"
    - "Update consumers: CI secret stores, deployed services, local .env files"
    - "Delete the leaked key with `aws iam delete-access-key`"
    - "Audit CloudTrail for unauthorized usage between leak time and revocation"
replacement_pattern: env_var
env_var_suggested_name: AWS_ACCESS_KEY_ID
secret_manager_recommendation:
  - AWS Secrets Manager
  - AWS Systems Manager Parameter Store
notes: |
  AWS keys are high-blast-radius. Always check CloudTrail.
```

**Mandatory fields:** `id`, `display_name`, `kingfisher_rules`, `severity_default`, `revocation.steps`, `replacement_pattern`. Everything else optional.

### 7.2 Generic fallback runbook (`_generic.yaml`)

Used when a finding's `kingfisher_rules` doesn't match any bundled runbook.

```yaml
id: _generic
display_name: Unknown / Unsupported Provider
kingfisher_rules: []
severity_default: high
revocation:
  console_url: ""
  api_command: ""
  steps:
    - "Identify the provider this credential belongs to"
    - "Locate the credential in the provider's admin console"
    - "Revoke or rotate the credential per the provider's documentation"
    - "Update any consumers (CI, deployed services, local env)"
    - "If possible, audit recent usage logs for unauthorized access"
replacement_pattern: env_var
env_var_suggested_name: SECRET_VALUE
notes: |
  No bundled runbook matched this finding's detection rule(s). Please file
  an issue at https://github.com/malamsyah/leakfix/issues with the rule ID
  so a provider-specific runbook can be added.
```

### 7.3 Rule matching policy

Rule IDs in `kingfisher_rules` use **prefix-matching, not exact-matching**, against the rule ID Kingfisher emits in its JSON. This guards against minor rule-ID drift across Kingfisher versions.

Examples:
- Runbook lists `kingfisher.aws.access_key`. Kingfisher emits `kingfisher.aws.access_key.v2`. **Match.**
- Runbook lists `kingfisher.github.pat`. Kingfisher emits `kingfisher.github.pat_classic`. **Match.**
- Runbook lists `kingfisher.stripe`. Kingfisher emits `kingfisher.stripe.live` and `kingfisher.stripe.test`. **Both match.**

If no runbook matches via prefix, fall back to `_generic`. Never error on rule-ID mismatch.

---

## 8. The `Plan` struct + redaction

### 8.1 The struct

Defined in `internal/plan/plan.go`. Contract between the agent and the executor.

```go
package plan

import "time"

// Plan is the output of Stage 2. It fully describes what
// leakfix intends to do for a given repo, before any side effects.
type Plan struct {
    RepoPath        string           `json:"repo_path"`
    BaseBranch      string           `json:"base_branch"`
    GeneratedAt     time.Time        `json:"generated_at"`
    KingfisherVer   string           `json:"kingfisher_version"`
    LeakfixVer      string           `json:"leakfix_version"`
    Items           []PlanItem       `json:"items"`
    HistoryRewrite  *HistoryRewrite  `json:"history_rewrite,omitempty"`
}

type PlanItem struct {
    FindingID       string        `json:"finding_id"`        // stable hash from Kingfisher
    Provider        string        `json:"provider"`          // e.g. "aws_iam_access_key"
    DisplayName     string        `json:"display_name"`
    Severity        Severity      `json:"severity"`          // critical | high | medium | low
    Validated       bool          `json:"validated"`         // Kingfisher said this is live
    AccessMap       *AccessMap    `json:"access_map,omitempty"`
    Locations       []Location    `json:"locations"`         // ≥1; one secret may appear in many places
    RunbookID       string        `json:"runbook_id"`        // matched runbook, or "_generic"
    RevocationSteps []string      `json:"revocation_steps"`  // copied from runbook
    ConsoleURL      string        `json:"console_url,omitempty"`
    CodeEdits       []CodeEdit    `json:"code_edits,omitempty"` // one per Location
    AgentRationale  string        `json:"agent_rationale"`
}

type Severity string

const (
    SeverityCritical Severity = "critical"
    SeverityHigh     Severity = "high"
    SeverityMedium   Severity = "medium"
    SeverityLow      Severity = "low"
)

type Location struct {
    File      string `json:"file"`
    Line      int    `json:"line"`
    CommitSHA string `json:"commit_sha,omitempty"`
}

type CodeEdit struct {
    File       string `json:"file"`
    OldContent string `json:"old_content"`     // raw line(s); redacted before render/transmit
    NewContent string `json:"new_content"`     // env-var reference
    EnvVarName string `json:"env_var_name"`
    Rationale  string `json:"rationale"`
}

type AccessMap struct {
    Identity    string   `json:"identity,omitempty"`
    Permissions []string `json:"permissions,omitempty"`
    Resources   []string `json:"resources,omitempty"`
}

type HistoryRewrite struct {
    Command     string   `json:"command"`
    SideEffects []string `json:"side_effects"`
    PostSteps   []string `json:"post_steps"`
}

// Validate ensures the Plan is structurally sound.
// It does NOT perform redaction — Redact() does that.
func (p *Plan) Validate() error { /* ... */ }

// Redact returns a copy of the Plan with all known literal secret values
// replaced by the placeholder. After Redact, no PlanItem may contain a
// literal secret, including in CodeEdit.OldContent.
// If a literal cannot be safely redacted (e.g., the agent didn't return a
// finding token to redact against), Redact returns an error.
func (p *Plan) Redact(secrets []string) (*Plan, error) { /* ... */ }
```

### 8.2 Redaction algorithm

The redactor replaces every occurrence of every known secret string in the Plan with a placeholder. The list of known secrets comes from Kingfisher's findings (the `secret` field of each finding).

**Placeholder format:**

For a secret `S` of length `n`:
- If `n ≤ 8`: replace entirely with `[REDACTED]`.
- If `n > 8`: keep first 4 and last 4 characters; replace middle with `…[REDACTED]…`. Example: `AKIAIOSFODNN7EXAMPLE` → `AKIA…[REDACTED]…MPLE`.

This preserves enough context for a human to identify the finding visually (in a diff or PR review) without leaking the credential.

**Algorithm:**

1. Collect all secret strings from Kingfisher findings into a set `S`.
2. Sort `S` by length descending (prevents partial replacement of substrings).
3. For each string field in the Plan (recursively): replace every occurrence of every `s ∈ S` with its placeholder.
4. Run a final scan: if any `s ∈ S` still appears in any string field, return an error. Plan is unsafe to render.

**Hard rule:** the redacted Plan is the only object permitted past Stage 3. The pre-redaction Plan is held only in memory inside the agent loop and used to apply `CodeEdit`s to the working tree (the executor needs the raw `OldContent` to find-and-replace), then discarded.

### 8.3 Logging redaction

`slog` calls at `info` level and above never receive raw Plan or Finding data. At `debug` level, redacted previews are permitted (using the same placeholder format). A custom `slog.Handler` enforces this — it scans every attribute against the known-secrets set before emitting.

---

## 9. Agent design (Stage 2)

### 9.1 Tool definitions exposed to the LLM

| Tool | Input | Output | Purpose |
|---|---|---|---|
| `list_providers` | — | `[]string` | Discover bundled runbooks |
| `lookup_runbook` | `provider_id: string` | `Runbook` | Retrieve a runbook (or `_generic`) |
| `read_file` | `repo_relative_path: string` | `string` (max 50KB) | Sandboxed read in target repo |
| `assess_finding` | `finding_id: string` | `{access_map, validation_status, locations}` | Get Kingfisher metadata |
| `propose_code_edit` | `file, find, replace_with, env_var_name, rationale` | `{ok, error_reason?}` | Stage an edit (validated against current file content; see 9.5) |
| `finalize_plan_item` | `plan_item_json: string` | `bool` | Commit the agent's output for one finding |

### 9.2 Prompts

In `internal/agent/prompts.go` as named string constants — one per logical prompt, never inlined.

- `SystemPromptPlan` — single Stage 2 system prompt (covers triage + planning together)
- `UserPromptTemplateFinding` — per-finding user message template

### 9.3 System prompt requirements

The system prompt MUST include these instructions explicitly:

- **Revocation comes before history rewrite. Always.**
- If `access_map` is empty, severity is best-effort; state this in `agent_rationale`.
- Code edits must be **minimal and reviewable** — replace the literal value with an env-var reference, do not delete the line, do not refactor adjacent code.
- The Plan MUST NOT contain the literal secret value anywhere except `CodeEdit.OldContent`, which is redacted before rendering.
- If no bundled runbook matches, use `_generic` and add a TODO.
- Prefer the runbook's suggested env-var name unless there's a clear reason not to.
- When a single secret appears in multiple files (Section 9.6), produce one `PlanItem` with multiple `Location`s and matching `CodeEdit`s, using the same env var name across all files.

### 9.4 Agent guardrails

Hard limits enforced in `internal/agent/guardrails.go`:

| Limit | Default | Why |
|---|---|---|
| Max iterations per finding | 8 | Prevent runaway tool-use loops |
| Max input tokens per finding | 20,000 | Cost ceiling |
| Max output tokens per finding | 4,000 | Cost ceiling |
| Max total findings per run | 50 (`LEAKFIX_MAX_FINDINGS`) | Cost ceiling |
| Per-finding timeout | 90s | Latency ceiling |
| Total run timeout | 15min | Latency ceiling |
| Max `read_file` bytes | 50KB | Bound context |

When a limit is hit:
- **Iterations / tokens / timeout exceeded:** the partial result is recorded with `agent_rationale = "agent loop exceeded <limit>; falling back to runbook defaults"`, and the runbook's defaults are used to fill in the Plan item. The run continues to the next finding.
- **Total findings exceeded:** the run errors out before the agent loop starts.

### 9.5 `propose_code_edit` validation

When the agent calls `propose_code_edit`, the tool implementation:

1. Reads the target file at the path the agent specified.
2. Confirms `find` matches the file's current content **exactly once**.
3. If `find` matches zero times → return `{ok: false, error_reason: "find string not present in file"}`. The agent retries.
4. If `find` matches more than once → return `{ok: false, error_reason: "find string is ambiguous; provide more context"}`. The agent retries with a longer find string.
5. If `find` matches exactly once → stage the edit and return `{ok: true}`.

This shifts the failure-mode surface from Stage 5 (apply-time) into the agent loop, where it can be fixed with a retry instead of aborting the run.

### 9.6 Multiple findings of the same secret

Kingfisher may report the same secret value at multiple locations. The agent must collapse these into a **single `PlanItem` with multiple `Location`s and a `CodeEdit` per location**, all using the same `EnvVarName`.

This is enforced upstream of the agent: `internal/scanner/kingfisher.go` deduplicates findings by `secret_hash`, producing one `Finding` with multiple `Location`s before passing to the agent. The agent never sees duplicate-secret findings as separate items.

### 9.7 Sandboxing

`read_file` is bounded to the target repo path. Any path that resolves outside it returns an error. Enforced in `internal/agent/tools.go` via `filepath.Rel` + prefix check. Symlinks that escape the repo are rejected.

---

## 10. What NOT to do

- ❌ Write custom detection rules. Kingfisher's are the source of truth.
- ❌ Build a web UI, TUI, or interactive prompt mode.
- ❌ Auto-revoke keys via provider APIs.
- ❌ Auto force-push after history rewrite.
- ❌ Add Gitleaks / TruffleHog ingestion in v1.
- ❌ Reimplement git operations from scratch. Use go-git for local ops; shell out for filter-repo.
- ❌ Inline LLM prompts at call sites. They live in `prompts.go`.
- ❌ Inline runbook YAML inside Go code. Use `go:embed`.
- ❌ Inline markdown templates as Go string literals. Use `internal/templates/` + `go:embed`.
- ❌ Add `--auto-yes`, `--force`, or equivalent flags.
- ❌ Take a dependency on a paid SaaS scanner.
- ❌ Add telemetry, analytics, or "phone home" functionality.
- ❌ Add a config file format in v1. Env vars + flags only.
- ❌ Process findings concurrently. Sequential in v1.
- ❌ Place the literal secret value into the rendered Plan, PR body, issue body, commit message, or info-level logs. Debug-level logs may contain redacted previews only.
- ❌ Use exact-match for Kingfisher rule IDs. Prefix-match (Section 7.3).
- ❌ Treat the same secret in multiple files as separate findings. Collapse them (Section 9.6).

---

## 11. Templates

### 11.0 Render contexts

Each template receives a specific render context. Defining these explicitly prevents drift between the templates and the renderer.

| Template | Render context type | Source |
|---|---|---|
| `plan.md.tmpl` | `Plan` (post-redaction) | `internal/plan/plan.go` |
| `pr_body.md.tmpl` | `PRRenderContext` (Plan + IssueNumber) | post-issue-creation |
| `issue_body.md.tmpl` | `IssueRenderContext` (Plan + PRNumber) | post-PR-creation |
| `report.md.tmpl` | `ReportRenderContext` (Plan + execution outcomes) | post-execute |

`PRRenderContext`, `IssueRenderContext`, and `ReportRenderContext` are defined in `internal/plan/render.go`:

```go
type PRRenderContext struct {
    Plan        *Plan
    IssueNumber int  // 0 if --no-issue
}

type IssueRenderContext struct {
    Plan      *Plan
    PRNumber  int
}

type ReportRenderContext struct {
    Plan          *Plan
    PRURL         string
    IssueURL      string  // empty if --no-issue
    BranchName    string
    Failures      []ExecutionFailure  // empty on full success
}
```

Stage 5 ordering: open issue first (PR body needs `IssueNumber`), then open PR, then update issue body to include `PRNumber` (extra GitHub call).

### 11.1 Dry-run markdown plan (`templates/plan.md.tmpl`)

````markdown
# Remediation plan for {{.RepoPath}}

Generated: {{.GeneratedAt}}
leakfix {{.LeakfixVer}} · kingfisher {{.KingfisherVer}}

## Summary

- **Findings:** {{len .Items}}
- **Critical:** {{count_severity .Items "critical"}}
- **High:** {{count_severity .Items "high"}}
- **Validated (live) credentials:** {{count_validated .Items}}

{{range $i, $item := .Items}}
---

## {{add $i 1}}. {{.DisplayName}}
{{range $loc := .Locations}}
- `{{$loc.File}}:{{$loc.Line}}`
{{end}}

**Severity:** {{.Severity}}{{if .Validated}} (validated as live by Kingfisher){{end}}
{{if .AccessMap}}**Blast radius:** {{.AccessMap.Identity}} — permissions: {{join .AccessMap.Permissions ", "}}{{end}}

### Revocation steps

{{range $step := .RevocationSteps}}
1. {{$step}}
{{end}}

{{if .ConsoleURL}}**Console:** {{.ConsoleURL}}{{end}}

### Proposed code changes

{{range $edit := .CodeEdits}}
**`{{$edit.File}}`**:
```diff
- {{$edit.OldContent}}
+ {{$edit.NewContent}}
```
{{end}}

Replace the literal with `{{(index .CodeEdits 0).EnvVarName}}`. Set this in your secret manager and CI environment.

### Why this plan

{{.AgentRationale}}

{{end}}

{{if .HistoryRewrite}}
---

## ⚠️ Optional: rewrite history

```bash
{{.HistoryRewrite.Command}}
```

### Side effects

{{range $effect := .HistoryRewrite.SideEffects}}
- {{$effect}}
{{end}}

### After running

{{range $i, $step := .HistoryRewrite.PostSteps}}
{{add $i 1}}. {{$step}}
{{end}}
{{end}}

---

## What leakfix did NOT do

- ❌ Revoke any keys (do this yourself using the steps above)
- ❌ Push or force-push any branches
- ❌ Modify your repo (this was a dry run; re-run with `--apply` to create a PR)
````

### 11.2 PR body (`templates/pr_body.md.tmpl`)

Render context: `PRRenderContext`. Reference `.Plan.Items`, `.IssueNumber`.

````markdown
# Replace leaked secrets with environment variable references

This PR was generated by [`leakfix`](https://github.com/malamsyah/leakfix). It addresses {{len .Plan.Items}} secret leak(s) detected by Kingfisher.

## ⚠️ Before merging: revoke the leaked keys

The keys themselves remain valid until **you** revoke them. This PR refactors the code; it does not invalidate the leaked credentials.

{{range $i, $item := .Plan.Items}}
## {{add $i 1}}. {{.DisplayName}}

**Finding ID:** `{{.FindingID}}`{{if .Validated}} · **Validated as live**{{end}}

Locations:
{{range $loc := .Locations}}- `{{$loc.File}}:{{$loc.Line}}`
{{end}}

### Revocation steps

{{range $step := .RevocationSteps}}
- [ ] {{$step}}
{{end}}

{{if .ConsoleURL}}**Console:** {{.ConsoleURL}}{{end}}

### Code change in this PR

Replaced the literal value with `{{(index .CodeEdits 0).EnvVarName}}`. You will need to set this in:

- [ ] CI secret store (GitHub Actions, etc.)
- [ ] Deployed environments
- [ ] Local development setup (`.env`)

{{end}}

---

🤖 Generated by [leakfix](https://github.com/malamsyah/leakfix){{if .IssueNumber}} · Tracking issue: #{{.IssueNumber}}{{end}}
````

### 11.3 Issue body (`templates/issue_body.md.tmpl`)

Render context: `IssueRenderContext`.

````markdown
# Secret leak remediation tracker

`leakfix` detected {{len .Plan.Items}} secret leak(s). PR #{{.PRNumber}} contains the code refactor. **This issue tracks the manual work.**

## Per-finding checklist

{{range $i, $item := .Plan.Items}}
### {{add $i 1}}. {{.DisplayName}} — `{{.FindingID}}`

- [ ] Key revoked
- [ ] Replacement key generated
- [ ] CI secret updated
- [ ] Deployed environments updated
- [ ] Usage audited (if logs available)
- [ ] PR #{{$.PRNumber}} merged

{{end}}

## Decision: rewrite history?

The leaked credentials remain in git history. Rewriting history removes them, but has side effects (commit SHAs change, signatures dropped, contributors must re-clone).

**leakfix's recommendation:** if all keys are revoked, history rewrite is usually unnecessary. Rewrite only if:

- The repository is or will become public, AND
- Some leaked credentials cannot be revoked (rare)

To rewrite, run `leakfix remediate <repo> --apply --rewrite-history`.

---

🤖 Created by [leakfix](https://github.com/malamsyah/leakfix). PR: #{{.PRNumber}}
````

### 11.4 Template helper functions

Defined in `internal/templates/helpers.go`. Registered into `template.FuncMap` for all four templates.

| Function | Signature | Purpose |
|---|---|---|
| `add` | `func(a, b int) int` | Index arithmetic in `range` |
| `sub` | `func(a, b int) int` | Index arithmetic |
| `join` | `func(elems []string, sep string) string` | Slice → string |
| `count_severity` | `func(items []PlanItem, sev string) int` | Summary counts |
| `count_validated` | `func(items []PlanItem) int` | Summary counts |
| `redact` | `func(s string) string` | Reapply redaction in templates as a defense-in-depth measure |
| `default` | `func(val, fallback string) string` | Empty-string fallback |

`redact` in templates is defense-in-depth — the Plan is already redacted by Stage 3, but if anything slipped through, the template-level redactor catches it. It uses the same algorithm as Section 8.2.

---

## 12. Error handling philosophy

- **Subprocess failures (Kingfisher, git-filter-repo)** surface stderr verbatim and exit non-zero. Don't try to interpret or wrap.
- **Anthropic API errors** retry with exponential backoff up to 3 times for 429 / 5xx. Other errors fail the run.
- **GitHub API errors** retry once on 5xx; surface 4xx with the API's error message.
- **Partial failures during `--apply`** (PR opened, issue creation failed) surface a warning but do not roll back the PR. Post-execution report lists what succeeded and what didn't.
- **Plan validation / redaction failure** is a hard error. The run aborts before any side effects.
- **Missing prerequisite** → `doctor`-style diagnostic message, do not attempt substitution.

### 12.4 Code edit application failure

If a `CodeEdit` validated successfully at `propose_code_edit` time but fails to apply at Stage 5 (file changed between scan and apply, encoding mismatch, etc.):

1. Skip just that edit. Do not abort the entire run.
2. Record an `ExecutionFailure` for the report.
3. Continue with remaining edits.
4. The PR is opened with the edits that did succeed; the failed edit is listed in the PR body under a "⚠️ Could not apply automatically" section.

This is a deliberate trade-off: a partially-successful PR is more useful than no PR at all, as long as the failure is clearly surfaced.

Never silently fall back to a less-safe behavior. If something can't be done correctly, surface the failure.

---

## 13. Operational behaviors

### 13.1 Branch naming

Generated branch name: `leakfix/remediate-<short-hash>`

Where `<short-hash>` is the first 8 chars of `sha256(sorted(FindingIDs))` of the Plan's items. Same set of findings → same branch name across runs (enables idempotency, Section 13.3).

### 13.2 Commit message

Single commit per `--apply` run, in conventional-commit style:

```
fix(security): replace leaked secrets with env var references

Generated by leakfix. Addresses N secret leak(s) detected by Kingfisher:

- AWS IAM Access Key in internal/config/dev.go
- GitHub PAT in scripts/release.sh

Tracking issue: #<issue_number>
Plan: <plan_hash>

🤖 Generated by leakfix v<version>
```

The commit message MUST NOT contain literal secret values. Verified by re-running redaction on the message before committing.

### 13.3 Idempotency on re-runs

If the user runs `leakfix remediate <repo> --apply` twice with the same findings, the second run:

1. Computes the would-be branch name (same hash → same name).
2. Checks if the branch already exists locally or remotely.
3. If it exists and an open PR points to it: skip with message `"PR #<n> already open for this set of findings; use --force-recreate to redo"`. Do not create a new PR.
4. If the branch exists but no open PR: surface a warning and exit non-zero. Don't push to a stale branch silently.

`--force-recreate` is **not** implemented in v1. The user manually deletes the branch / closes the PR and re-runs.

### 13.4 Dirty working tree

If `git status` shows uncommitted changes when `--apply` runs:

1. Refuse to proceed. Exit with: `"working tree is dirty; commit or stash changes before running --apply"`.
2. No `--allow-dirty` flag. The cost of one extra command is small; the cost of accidentally including unrelated changes in the PR is large.

`scan` and dry-run `remediate` work fine on dirty trees — they're read-only.

### 13.5 Auth for Kingfisher's `--access-map`

Kingfisher's `--access-map` for AWS findings requires AWS credentials to be available in the env where Kingfisher runs. `leakfix` does not pass AWS credentials through; it inherits the environment, same as if the user invoked `kingfisher` directly. This is documented in `docs/ARCHITECTURE.md`.

---

## 14. Testing strategy

### 14.1 Unit tests (deterministic, no network)

- `internal/scanner/`: parse fixture Kingfisher JSON; test malformed input handling.
- `internal/runbooks/`: load all bundled runbooks; verify required fields; verify no duplicate `id`s; verify `_generic.yaml` exists; test prefix matching (Section 7.3).
- `internal/plan/`: validate; redact (test all redaction edge cases including overlapping secrets, short secrets, secrets with regex special chars); render templates against a sample Plan; snapshot outputs.
- `internal/git/`: branch + commit + push tests against a temp local bare repo (no network); branch naming determinism.
- `internal/agent/guardrails.go`: limits enforced correctly.

### 14.2 Agent loop tests (mocked LLM)

The Anthropic client is behind an interface (`internal/agent/client.go`):

```go
type Client interface {
    Complete(ctx context.Context, req Request) (Response, error)
}
```

For tests, a `mockClient` returns canned tool-use sequences. Test cases:
- Happy path: single AWS finding → plan with correct runbook
- Unknown provider → falls back to `_generic`
- Same secret in 3 files → one PlanItem with 3 Locations + 3 CodeEdits
- Iteration limit hit → fallback recorded in `agent_rationale`
- `propose_code_edit` with non-matching `find` string → tool returns error, agent retries
- Agent attempts to put literal secret in `agent_rationale` → redaction strips it

### 14.3 Integration tests (require `kingfisher` on PATH)

Gated behind `-tags=integration`:

- `leakfix scan testdata/fixtures/aws-leak` returns at least 1 finding
- `leakfix remediate testdata/fixtures/aws-leak` (dry-run, mocked LLM) produces a redacted plan
- Idempotency: running `--apply` twice creates only one branch

### 14.4 End-to-end tests (require live API keys, manual)

Documented in `docs/ARCHITECTURE.md`. Not part of CI. Run before each release.

### 14.5 Self-scan as a release gate

Before tagging any release, CI runs `leakfix scan .` against the leakfix repo itself. If it finds anything, the release is blocked.

### 14.6 `.golangci.yml`

Minimum configuration. Add linters as needed but don't disable these without justification.

```yaml
run:
  go: "1.22"
  timeout: 5m

linters:
  enable:
    - errcheck
    - govet
    - ineffassign
    - staticcheck
    - unused
    - gosec       # security-focused; warns on anything that looks like crypto/exec misuse
    - gocritic
    - revive
    - misspell
    - bodyclose

linters-settings:
  gosec:
    # Allow os/exec since we shell out to kingfisher and git-filter-repo
    excludes:
      - G204  # Subprocess launched with variable

issues:
  exclude-rules:
    - path: _test\.go
      linters:
        - gosec
        - errcheck
```

---

## 15. Acceptance criteria (v1 done)

- [ ] `leakfix doctor` passes on a clean machine with kingfisher, git-filter-repo, gh CLI, `ANTHROPIC_API_KEY`.
- [ ] `leakfix scan testdata/fixtures/aws-leak --format json` outputs at least one finding.
- [ ] `leakfix remediate testdata/fixtures/aws-leak` (dry-run) outputs a markdown plan that:
  - Correctly identifies the provider as AWS IAM.
  - Includes revocation steps from the bundled runbook.
  - Proposes a code edit replacing the literal with `os.Getenv("AWS_ACCESS_KEY_ID")` (or equivalent).
  - Contains NO literal secret values (post-redaction; verified by string search).
  - Renders cleanly via the markdown template.
- [ ] `leakfix remediate testdata/fixtures/multi-leak` correctly collapses the same secret in multiple files into one PlanItem.
- [ ] `leakfix remediate <fork> --apply` creates a real PR and tracking issue, both rendering cleanly and cross-referencing each other.
- [ ] `leakfix remediate <repo> --apply` run twice does not create a duplicate PR (idempotency).
- [ ] `leakfix remediate <repo> --apply` on a dirty working tree refuses with a clear message.
- [ ] `leakfix remediate <repo> --rewrite-history` emits the exact `git-filter-repo` command, lists side effects, and does NOT execute force-push.
- [ ] All 6 provider runbooks present and load successfully. `_generic.yaml` is the fallback.
- [ ] `Plan.Validate()` + `Plan.Redact()` reject any plan containing the literal secret value post-redaction.
- [ ] Agent guardrails (iterations, tokens, timeout) all enforced and tested.
- [ ] `propose_code_edit` validation rejects non-matching `find` strings before staging.
- [ ] `README.md` present.
- [ ] CI runs `golangci-lint` + `go test ./...` on every PR.
- [ ] CI runs `leakfix scan .` against itself before release.
- [ ] `LICENSE` is Apache 2.0.
- [ ] Test fixtures use clearly-fake secret patterns. No real keys, ever.

---

## 16. Suggested generation order

Each step should leave the repo in a working state.

1. **Bootstrap** — `go mod init`, file layout, empty packages, `cobra` skeleton, `.golangci.yml`.
2. **`doctor`** — cheapest end-to-end loop; proves the dependency chain.
3. **Runbooks** — write 6 YAML files + `_generic.yaml`, the loader with prefix-matching, and `leakfix runbook`. Pure data.
4. **Plan struct + redaction** — define `plan.Plan`, write `Validate()` and `Redact()`. Test redaction extensively (Section 14.1).
5. **Templates + helpers** — write the 4 markdown templates, the helper functions, and the renderer. Test against a hard-coded sample `Plan`.
6. **Scanner wrapper** — subprocess Kingfisher, parse JSON, deduplicate findings by secret hash. Implement `leakfix scan`.
7. **Mock-driven agent loop** — wire up Anthropic client interface, define tools (including `propose_code_edit` validation), write the loop. Test via `mockClient`. Largest chunk.
8. **Live agent loop** — point the agent at the real API. Verify against a fixture.
9. **Git operations + conventions** — branch naming, commit message, branch + commit + push via go-git. Test on a local throwaway clone.
10. **GitHub PR/issue creation** — render contexts; ordering (issue first, then PR, then update issue with PR number).
11. **`--apply` end-to-end** — stitch 7+8+9+10. Add idempotency check + dirty-tree refusal.
12. **`--rewrite-history`** — emit-only.
13. **Final report writer** — render context + template.
14. **Polish** — README polish, ARCHITECTURE.md, PROVIDERS.md, ROADMAP.md, CI workflows, goreleaser.

If any step takes more than ~3 hours and isn't done, stop and re-scope.

---

## 17. Pre-flight + version pinning

### 17.1 Pre-flight checks for Claude Code

Before generating, verify:

1. **Anthropic Go SDK** — check the latest version on https://docs.claude.com and the GitHub releases. Pin to a specific version in `go.mod`. If a stable Go binding for the Claude Agent SDK exists, prefer it; otherwise use the bare API client with tool use.
2. **Kingfisher CLI** — run `kingfisher scan --help` and `kingfisher --version`. Confirm the JSON output schema referenced in `internal/scanner/types.go` matches what the binary emits. If the schema has drifted, update types **before** writing parser code.
3. **`git-filter-repo`** — verify available via `git filter-repo --help`.
4. **Go version** — require 1.22+ in `go.mod`.
5. **`gh` CLI** — fallback auth source.

If any prerequisite is missing or has drifted, **halt and surface it** rather than substituting.

### 17.2 Kingfisher version pinning policy

- Declare a supported version range in `internal/scanner/version.go` (e.g., `>=0.6.0, <1.0.0`).
- `leakfix doctor` runs `kingfisher --version` and compares to the supported range.
- If outside the range: warn (don't error) and recommend upgrading. Run continues — Kingfisher's JSON schema is reasonably stable across minors.
- The supported range is bumped in lockstep with Kingfisher releases. When a new major (e.g., 1.0) lands, hold off on bumping until the schema is verified manually.
- The schema parser uses `json.Unmarshal` with **non-strict** field handling (`json.Decoder.DisallowUnknownFields()` is OFF). New fields in Kingfisher output do not break parsing.

---

## 18. Effort budget

Target: **25–30 hours** of focused work for v1.

Expect the agent loop (steps 7–8) to be ~40–50% of the time. Trim elsewhere.

If v1 isn't shippable after **40 hours**, the scope was wrong. Cut features. Likely cuts: drop one or two provider runbooks, drop `--rewrite-history` (defer to v0.2), drop the tracking issue (just open the PR).

---

## 19. README one-liner (locked)

> **`leakfix`** — Remediation agent for Kingfisher findings. Generates per-provider revocation runbooks, opens review-ready PRs, and (optionally) scrubs git history — with side effects spelled out, not hidden.

---

## 20. Roadmap (post-v1, do not build now)

- **v0.2** — cross-tool ingestion (Gitleaks + TruffleHog JSON → unified findings).
- **v0.3** — concurrent finding processing with rate-limit awareness.
- **v0.4** — GitLab + Bitbucket support.
- **v0.5** — org-wide scanning mode.
- **v0.6** — optional auto-revoke for low-risk providers behind an explicit flag.
- **v1.0** — SaaS / hosted version. Maybe.