# Adding a provider runbook

Adding a new provider is a YAML-only change.

1. Find the Kingfisher rule ID(s) you want to handle. Run `kingfisher rules list`
   or grep the [Kingfisher rules repo](https://github.com/mongodb/kingfisher).
2. Create `internal/runbooks/data/<provider>.yaml` following the schema below.
3. Add a happy-path test case to `internal/runbooks/runbooks_test.go::TestMatch_PrefixMatching`.
4. `go test ./...` must still pass.

## Schema

```yaml
id: my_provider                    # unique, lowercase, snake_case
display_name: My Provider Service  # human-readable, used in plan titles
kingfisher_rules:                  # PREFIX-matched, not exact-matched
  - kingfisher.myprovider.api_key
severity_default: high             # critical | high | medium | low
revocation:
  console_url: https://myprovider.com/dashboard/api-keys
  api_command: |
    # optional: the command users can run themselves
    curl -X DELETE https://api.myprovider.com/keys/<KEY_ID>
  steps:
    - "Locate the leaked key in the provider dashboard"
    - "Click 'revoke' on the leaked key"
    - "Generate a replacement"
    - "Update consumers (CI, deployed services, .env)"
    - "Audit recent activity for unauthorized access"
replacement_pattern: env_var
env_var_suggested_name: MYPROVIDER_API_KEY
secret_manager_recommendation:
  - 1Password
  - Vault
notes: |
  Optional free-form notes shown in agent context.
```

**Required fields:** `id`, `display_name`, `kingfisher_rules`, `severity_default`,
`revocation.steps`, `replacement_pattern`. Everything else is optional.

## Prefix matching

`kingfisher_rules` are matched as **prefixes** of the rule ID Kingfisher
emits. This guards against minor rule-ID drift across Kingfisher versions:

- Runbook lists `kingfisher.aws.access_key`. Kingfisher emits
  `kingfisher.aws.access_key.v2`. **Match.**
- Runbook lists `kingfisher.stripe`. Kingfisher emits both
  `kingfisher.stripe.live` and `kingfisher.stripe.test`. **Both match.**

If no runbook matches via prefix, leakfix falls back to `_generic.yaml`. Never
error on rule-ID mismatch.

## What about non-revocable secrets?

Some providers don't expose a programmatic revoke API (Slack webhooks,
historically GitHub PATs). Document this clearly in the `revocation.steps` and
keep `api_command` empty or include a comment that explains the limitation.
