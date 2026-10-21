# Case study — Firebase JS, AWS Amplify JS, Ory Hydra

- **Scanned repositories:**
  - [`firebase/firebase-js-sdk`](https://github.com/firebase/firebase-js-sdk)
  - [`aws-amplify/amplify-js`](https://github.com/aws-amplify/amplify-js)
  - [`ory/hydra`](https://github.com/ory/hydra)
- **Scanned revision:** `main` as of 2026-10-21
- **Scanner version:** `identity-trust-hunt==0.3.0`

## Headline

**All three clean under PTB v0.3 at `--min-confidence 0.6`.** Zero
hits across every repository with the path-weight filter applied.
No vendor disclosure needed.

## Why they were targeted

These are three of the most-deployed OSS identity integrations:

- **Firebase JS SDK** — Google-owned, 5k+ GitHub stars, foundation
  for every Firebase-backed consumer app.
- **AWS Amplify JS** — AWS-owned, 10k+ stars, the Cognito-adjacent
  SDK for every Amplify-backed consumer app.
- **Ory Hydra** — OAuth 2.0 and OIDC provider in Go, used as the
  authority in many enterprise self-hosted stacks.

If any of them shipped the PTB bug class, the blast radius would
be very large. They do not.

## What was evaluated

Full repository scan with the public v0.3 provider dictionary.
`.ts/.tsx/.js/.mjs/.cjs/.go/.py/.rb/.java/.kt/.cs/.php/.rs/.swift`
extensions covered. Path-weight filter at 0.6 cut
`test/` / `tests/` / `spec/` / `__tests__/` / `fixtures/` /
`demo/` / `locale/` noise.

## Confirmed findings

None.

## Reviewer notes

### Firebase JS SDK

Firebase outsources provider-trust decisions to the Firebase
Authentication backend rather than reconstructing them inside the
JS SDK. The SDK is a credential carrier, not a trust evaluator.
PTB-unsafe sites, if any, would live inside the (closed-source)
Authentication backend; the SDK itself is a necessary-not-sufficient
clearance from the open-source side.

### AWS Amplify JS

Amplify uses Cognito as the identity authority. Email trust
decisions are enforced inside Cognito (closed-source) and
delivered through signed tokens; the Amplify SDK unpacks tokens
rather than making trust decisions on raw claims. Same
necessary-not-sufficient shape as Firebase.

### Ory Hydra

Hydra implements the OAuth 2.0 / OIDC server side rather than the
consumer side. It issues tokens; it does not consume
Microsoft / GitHub / Apple / Google provider claims. The PTB
predicate applies to CONSUMERS of provider claims, so Hydra sits
on the other side of the trust boundary and is architecturally
out of PTB's current scope.

(Ory Kratos is the identity-management companion; it was scanned
in the same sweep and also returned no high-confidence findings
inside the provider dictionary.)

## Takeaway

Three of the biggest identity integrations in the open-source JS
and Go ecosystems pass PTB v0.3. That matches the posture their
owners (Google, AWS, Ory) have publicly signaled around identity
security. The framework's negative results on these targets
calibrate how aggressively to interpret positive results on the
smaller surfaces where PTB-unsafe code HAS been found (Supabase,
Hanko, Documenso, Auth.js, Keycloak, Casdoor, better-auth).
