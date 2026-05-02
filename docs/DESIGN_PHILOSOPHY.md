# Design philosophy

Three principles. Non-negotiable for v1. Deviate only with explicit
justification in the PR description.

## 1. Revoke first. History rewrite is opt-in.

GitHub's [own guidance](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository)
is unambiguous: **if a leaked credential can be revoked, that often *is* the fix**.
Rewriting history has serious side effects:

- Commit SHAs change.
- GPG / SSH commit signatures get dropped.
- Open PR diffs invalidate.
- Any collaborator who pushes their old clone re-contaminates the repo.

leakfix's primary output is therefore the **revocation runbook**. History
rewrite is gated behind `--rewrite-history` and accompanied by loud warnings.

## 2. Wrap, don't reinvent.

Detection rules → [Kingfisher](https://github.com/mongodb/kingfisher).
History rewriting → [`git-filter-repo`](https://github.com/newren/git-filter-repo).
PR / issue creation → GitHub API.

leakfix's value is the orchestration *above* these. Resist any impulse to
write custom detection rules or a custom history-rewrite engine. Resist the
urge to "absorb" what these tools do "while we're here". Stay thin.

## 3. Generate the action; don't execute the irreversible.

The agent produces:

- ✅ A revocation runbook (markdown + console URL + provider command)
- ✅ A `git-filter-repo` invocation
- ✅ A pull request and tracking issue

It never:

- ❌ Calls a provider API to revoke a key
- ❌ Force-pushes a rewritten history
- ❌ Deletes refs

Reversible operations are automated. Irreversible ones remain the human's
responsibility — explicitly, deliberately, with no `--auto-yes`,
`--force`, or `--no-confirm` flag.

## Why so opinionated?

Most secret-leak tools push you toward `git filter-repo` as the *first* step.
That guidance is wrong: rewriting history without revoking the key still leaves
a live credential on the open internet (in old clones, mirrors, and any cache
that scraped it). The opinionated default — *revoke first, history-rewrite
last, and only if you really need it* — is the actual security posture.

The cost of being opinionated is occasionally getting in the user's way. The
benefit is that anyone reading a leakfix PR can trust that the behavior was
considered, not accidental.
