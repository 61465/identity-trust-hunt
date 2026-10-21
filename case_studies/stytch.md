# Case study — Stytch (`stytchauth/stytch-node`)

- **Scanned repository:** [`stytchauth/stytch-node`](https://github.com/stytchauth/stytch-node)
- **Scanned revision:** `main` as of 2026-10-21
- **Scanner version:** `identity-trust-hunt==0.1.0`

## Headline

**Clean under PTB v0.1.** Zero hits across the full repository.
No vendor disclosure needed.

## What was evaluated

The scanner ran across the full `stytch-node` SDK with the public
v0.1 provider dictionary (8 providers × 1 claim each). No access
pattern fired the detector.

## Confirmed findings

None.

## False positives surfaced

None at v0.1 narrowing. (The pre-narrowing dictionary matched 14
occurrences on substrings like `apple` / `discord` / `twitter` in
SDK comment blocks and type names; v0.1 narrows access patterns to
API-endpoint URLs and SDK-specific symbol names, which removes
every such false positive.)

## Vendor channel

No disclosure needed.

## Reviewer notes

Stytch's SDK is a thin wrapper over Stytch's own API; it does not
re-implement provider trust contracts. That design shape puts the
trust decision inside Stytch's platform rather than in the SDK, so
PTB-unsafe sites — if they exist — would live in the Stytch
platform code (not public) rather than in the open-source SDK.
PTB v0.1 can only reason about public source; the SDK scan is a
necessary-not-sufficient result.
