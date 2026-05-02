# leakfix roadmap

This file lists features that are **not** in v1 and not currently being worked on.
PRs that add features beyond the v1 scope will be politely closed and added here.

## v0.2 (next)
- Cross-tool ingestion: Gitleaks + TruffleHog JSON → unified findings (with cross-tool dedup).

## v0.3
- Concurrent finding processing with rate-limit awareness.

## v0.4
- GitLab + Bitbucket support.

## v0.5
- Org-wide / multi-repo scanning mode.

## v0.6
- Optional auto-revoke for low-risk providers, gated behind an explicit flag.

## v1.0 (maybe)
- Hosted SaaS version. Strictly opt-in; OSS path remains the headline.

---

If your idea isn't on this list and isn't on the v1 acceptance criteria, please
open an issue *before* writing the PR.
