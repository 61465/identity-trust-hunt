# Case study — Clerk (`clerk/javascript`)

- **Scanned repository:** [`clerk/javascript`](https://github.com/clerk/javascript)
- **Scanned revision:** `main` as of 2026-10-21
- **Scanner version:** `identity-trust-hunt==0.1.0`

## Headline

**Clean under PTB v0.1.** Four low-confidence hits surfaced; a human
reviewer dismissed all four as detector false positives. No vendor
disclosure needed.

## What was evaluated

The scanner ran across the full repository with the public v0.1
provider dictionary (8 providers × 1 claim each). All provider rows
fired the detector; the engine reported four potential PTB-unsafe
sites.

## Confirmed findings

None. The scanner found no site where consumer code reads an
identity-provider claim without the provider's required guard.

## False positives surfaced

| Site | Claim | Why dismissed |
|---|---|---|
| `packages/localizations/src/en-US.ts:802` | Azure email | A localization string containing the expression `user.profile.email` — not a claim consumer, just an error-message template. |
| `packages/msw/SignInService.ts:67` | GitHub email | A Mock Service Worker fixture (`primary: true`) used in test setup — not a real consumer. |
| `packages/ui/src/components/UserProfile/MfaPhoneCodeScreen.tsx:214` | GitHub email | A localization key named `primaryButton__addPhoneNumber`. The substring `primary` matched the detector but the surrounding context is UI, not identity. |
| `packages/ui/src/foundations/colors.ts:114` | GitHub email | A CSS color token (`primaryHover`). Unrelated. |

The common dismissal reason — the GitHub detector matches on
`primary: true` because the GitHub `/user/emails` API uses that
field; the string appears broadly in UI code. v0.2 will narrow this
guard to co-location with a `/user/emails` endpoint access pattern,
removing all three UI dismissals.

## Vendor channel

No disclosure needed. Clerk's auth code passes PTB v0.1.

## Reviewer notes

Clerk already [publishes product-level guidance on provider trust
differences](https://clerk.com/articles/easie-sso-what-it-is-and-which-providers-support-it-2);
the auth-code cleanness is consistent with that posture.
