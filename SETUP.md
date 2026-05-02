# Setup

`leakfix` is a CLI orchestrator: it shells out to other tools rather than
reimplementing their work. To run it, you need four things installed.

## TL;DR

```bash
git clone https://github.com/malamsyah/leakfix
cd leakfix
make setup        # installs gh + git-filter-repo + kingfisher (best-effort)
make build        # produces ./bin/leakfix
./bin/leakfix doctor
```

If anything red appears in `doctor`, see [troubleshooting](#troubleshooting) below.

## What you need

| Tool | Why | Required for |
|---|---|---|
| Go 1.22+ | to build leakfix | building from source |
| [`kingfisher`](https://github.com/mongodb/kingfisher) (>= 0.6.0) | the detection + validation + access-map layer | `scan`, `remediate` |
| [`git-filter-repo`](https://github.com/newren/git-filter-repo) | history-rewrite plan | `remediate --rewrite-history` only |
| [`gh`](https://cli.github.com/) **or** `GH_TOKEN` | GitHub auth | `remediate --apply` only |
| `ANTHROPIC_API_KEY` env var | the planning agent | `remediate` only |

`scan` and `doctor` work as soon as `kingfisher` is on PATH. The other deps
are only required for the `remediate` flows.

## macOS (Homebrew)

```bash
make setup
```

This runs:

```bash
brew install gh git-filter-repo kingfisher
```

Then export your Anthropic key in your shell profile:

```bash
echo 'export ANTHROPIC_API_KEY=sk-ant-...' >> ~/.zshrc
source ~/.zshrc
```

## Linux (Debian / Ubuntu)

```bash
sudo apt-get update
sudo apt-get install -y gh
pipx install git-filter-repo   # or: pip3 install --user git-filter-repo
make install-kingfisher        # uses cargo if available; otherwise points at releases
```

If `cargo` is not installed:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
```

Then:

```bash
cargo install --git https://github.com/mongodb/kingfisher kingfisher
```

Or download a prebuilt binary from
<https://github.com/mongodb/kingfisher/releases> and place it on `$PATH`.

## Manual install (any platform)

If `make setup` doesn't fit your environment, install each tool yourself:

- **kingfisher**: <https://github.com/mongodb/kingfisher/releases>
- **git-filter-repo**: <https://github.com/newren/git-filter-repo#how-do-i-install-it>
- **gh**: <https://cli.github.com/>
- **ANTHROPIC_API_KEY**: <https://console.anthropic.com/settings/keys>

Then run `make doctor` to verify everything resolves on PATH.

## Authentication

### GitHub

Either log into the GitHub CLI:

```bash
gh auth login
```

…or set a token with `repo` scope:

```bash
export GH_TOKEN=ghp_...
```

`leakfix` checks `gh auth token` first, then falls back to `GH_TOKEN`.

### Anthropic

```bash
export ANTHROPIC_API_KEY=sk-ant-...
```

Override the model (optional; defaults to the latest Sonnet):

```bash
export LEAKFIX_MODEL=claude-sonnet-4-6
```

### Remote / org-wide scans

`leakfix scan github.com/owner/repo` and `leakfix scan-org <owner>` shell out
to `kingfisher scan github`, which uses `KF_GITHUB_TOKEN` for both rate
limits and access to private repos. leakfix derives this automatically from
`GH_TOKEN`, `GITHUB_TOKEN`, or `gh auth token` — you do not need to set it
manually if you have any of those. To override:

```bash
export KF_GITHUB_TOKEN=ghp_...
```

Without a token, GitHub will rate-limit the listing API at ~60 requests/hour
and most org scans will fail with `401 Bad credentials`.

## Verifying

```bash
make doctor
```

A clean output looks like:

```
✓ Kingfisher                   kingfisher 0.6.2 (>=0.6.0 supported)
✓ git-filter-repo              git-filter-repo 2.45.0 (>=2.40.0 supported)
✓ gh CLI / GH_TOKEN            gh version 2.55.0 (...)  github.com
✓ ANTHROPIC_API_KEY            set (sk-ant-...3F2x)
✓ Go                           1.22.5 (>=1.22 supported)

All checks passed.
```

## Make targets

```
make help              # list every target
make build             # produce ./bin/leakfix
make doctor            # run leakfix doctor
make verify            # check just the scan-time prereq (kingfisher)
make test              # go test -race
make lint              # golangci-lint
make integration       # go test -tags=integration (needs kingfisher)
make self-scan         # leakfix scan . (CI release gate)
make setup             # install gh + git-filter-repo + kingfisher
```

`make setup` is best-effort: if a package manager is missing, it prints the
manual install steps for that tool and continues with the rest.

## Troubleshooting

**`kingfisher: executable file not found in $PATH`**
Run `make install-kingfisher`. If that fails, install manually:
<https://github.com/mongodb/kingfisher/releases>.

**`brew install kingfisher` fails**
Update Homebrew (`brew update`) and retry. Otherwise use
`cargo install --git https://github.com/mongodb/kingfisher kingfisher`
or grab a prebuilt binary from <https://github.com/mongodb/kingfisher/releases>.

**`gh auth status` shows "not logged in"**
Run `gh auth login` (interactive), or set `GH_TOKEN=ghp_...` for non-interactive use.

**`leakfix scan .` reports a finding in this repo**
The CI release gate fails on any self-scan finding. Either rotate the
credential or, if it's a documented test fixture, add a kingfisher
ignore comment. Test fixtures under `testdata/fixtures/` are scanned too —
they should use clearly-fake patterns (the AWS-published `AKIAIOSFODNN7EXAMPLE`
is fine, since it's not a real key).
