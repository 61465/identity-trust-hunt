# Case study — Dex (`dexidp/dex`)

- **Scanned repository:** [`dexidp/dex`](https://github.com/dexidp/dex)
- **Scanned revision:** `main` as of 2026-10-21
- **Scanner version:** `identity-trust-hunt==0.3.0`

## Headline

**Clean under PTB v0.3 at `--min-confidence 0.6`.** Three low-weight
hits surfaced; manual review found no PTB-unsafe sink. One
GitHub-Enterprise tradeoff is documented inline and scoped. No
vendor disclosure needed.

## What was evaluated

Full repository scan with the public v0.3 provider dictionary.
Path-weight filter at 0.6 cut noise from the `cmd/example-app/`
demo and the `/_test/` fixtures.

## Confirmed findings

None. The three high-signal hits all resolved to defensive
production code when read in context:

| Site | What the scanner matched | What the code actually does |
|---|---|---|
| `connector/github/github.go:682` | `/user/emails` + absent `verified` on the same line | Line 682 explicitly requires `email.Verified && email.Primary` before accepting an email. The scanner matched the request URL, not the trust decision. |
| `connector/bitbucketcloud/bitbucketcloud.go:341` | `/user/emails` + absent `verified` on the same line | Line 341 requires `email.IsConfirmed && email.IsPrimary`. Same shape as GitHub; same defensive pattern. |
| `connector/linkedin/linkedin.go:41` | LinkedIn-provider access without a `verifyEmail` guard | A scope-string declaration, not a consumer-side trust decision. Linkedin's `/userinfo` return is handled downstream against the OIDC spec. |

## Documented tradeoff — GitHub Enterprise verified bypass

`connector/github/github.go:672-680` deliberately marks every email
as verified when `c.hostName != ""`:

```go
// if GitHub Enterprise, set email.Verified to true
// This change being made because GitHub Enterprise does not
// support email verification. CircleCI indicated that GitHub
// advised them not to check for verified emails
// (https://circleci.com/enterprise/changelog/#1-47-1).
// In addition, GitHub Enterprise support replied to a support
// ticket with "There is no way to verify an email address in
// GitHub Enterprise."
if c.hostName != "" {
    email.Verified = true
}
```

This is a scope-limited, operator-known tradeoff: GitHub Enterprise
admins already control email provisioning, so the trust boundary
sits at the GHE server rather than at the Dex connector. The
behavior is documented inline, scoped to `hostName != ""` only, and
cites the vendor advisory it was based on. It is not a PTB finding
in the sense this framework uses the term.

## Vendor channel

No disclosure needed.

## Reviewer notes

Dex's connector pattern of `email.Verified && email.Primary` is
the exact fix shape the PTB framework recommends for consumer-side
GitHub integrations. Downstream vendors integrating with Dex can
treat Dex-brokered emails as trust-boundary-safe for the connectors
reviewed above, PROVIDED they are not routing through a
`hostName`-set Enterprise connector.
