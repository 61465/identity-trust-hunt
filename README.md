# identity-trust-hunt

**Reference implementation of the PTB framework — Provider Trust Boundary auditing for social-login integrations.**

`identity-trust-hunt` evaluates a target codebase against a taxonomy of
known Provider Trust Boundary (PTB) failure modes and surfaces call
sites that consume identity-provider claims without the verification
each provider's semantic contract requires.

The methodology was first formalized after two accepted CVSS 9.8
GHSAs for the Azure `xms_edov` sibling-ancestor pattern:
`GHSA-ffp4-94w6-vfgv` (Supabase) and `GHSA-2gvh-5vh3-m2rp` (Hanko).

This repository is the **public teaching edition (v0.1)**. The
methodology itself is fully documented in
[`docs/METHODOLOGY.md`](docs/METHODOLOGY.md); a subset of the
implementation (expanded detector dictionary, call-graph
propagation, ML-embedding fallback, prioritization-formula weights,
cross-language indexing) is retained as a NEXUS Zone research
artifact. See the IP split in
[`docs/METHODOLOGY.md`](docs/METHODOLOGY.md).

---

## The PTB predicate in one line

> For any call site `c` in system `W` that consumes a claim `k` from
> an identity provider `p`:
>
> ```
> c is PTB-unsafe ⟺ ∃ v ∈ V(p, k) such that v ∉ guards(c)
> ```

In plain English: every social-login provider ships a *semantic
contract* for each claim it returns (`V(p, k)` is the set of
verification steps a consumer MUST perform for claim `k` on provider
`p` to safely trust that claim). PTB-unsafe call sites are the ones
that read `k` without applying the required guards.

The classic case: Microsoft Azure returns `email` on OIDC. The
provider contract requires `xms_edov == "1"` before `email` can be
trusted as owned. A call site that reads `email` without checking
`xms_edov` is PTB-unsafe for the Azure provider — this is the
nOAuth bug class.

---

## The current detector set (v0.1 teaching dictionary)

| # | Provider | Claim | Required guard | Known public failure |
|---|---|---|---|---|
| 1 | Microsoft Azure OIDC | `email` | `xms_edov == "1"` | nOAuth (Descope, 2024); GHSA-ffp4-94w6-vfgv; GHSA-2gvh-5vh3-m2rp |
| 2 | Apple Sign in with Apple | `email` | `email_verified == true` **AND** `is_private_email` branch handled | public developer docs — `email_verified` is `"true"` even for user-edited values on first-login path |
| 3 | Google OIDC | `hd` | explicit domain pin or allow-list match | public — hosted-domain trust without pin is a documented anti-pattern (Google's own OIDC guidance) |
| 4 | Facebook Limited Login | JWT `email` | JWT-signature verified **AND** `email_verified` branch distinct from classic Login flow | 2024 Apple App-Store policy forced Limited Login; verifier skew is documented in Meta devrel |
| 5 | GitHub OAuth | `email` from `/user` | `verified: true` on the specific email, not just `primary: true` | GitHub docs explicitly separate `primary` from `verified` |
| 6 | Discord OAuth | `verified` on user object | boolean handling — some SDKs coerce `undefined` to `true` | Discord docs — field is nullable on new accounts |
| 7 | LinkedIn OpenID Connect | `email` | LinkedIn provides no `email_verified` field; consumers MUST either reject the provider for email-trust use cases, or require a separate email challenge | LinkedIn OIDC spec gap, public |
| 8 | Twitter / X OAuth 2.0 | `email` | email can change after token issuance; stale cached email is PTB-unsafe for trust gating | Twitter / X developer docs, token-independence section |

The dictionary is maintained under `identity_trust_hunt/providers/`.
Entries are evidence-anchored: each row cites either a public
provider doc, a public CVE/GHSA, or a public conference talk.

Rows WITHOUT a public citation live in the retained research
dictionary and are not shipped in this teaching edition.

---

## Install

```bash
pip install identity-trust-hunt
```

Requires Python ≥ 3.10 and `git` on `PATH`. The package has no
runtime dependencies beyond the standard library.

From source:

```bash
git clone https://github.com/61465/identity-trust-hunt
cd identity-trust-hunt
pip install -e .[dev]
pytest -v
```

---

## Example — scan a repo for Azure xms_edov miss

```bash
identity-trust-hunt scan ./my-auth-service --provider azure --claim email
```

Sample output:

```
identity-trust-hunt v0.1

target        ./my-auth-service
provider      Microsoft Azure OIDC
claim         email
required      xms_edov == "1"

[PTB-UNSAFE]  src/auth/oidc-azure.ts:88
  context     claims["email"] consumed as account identity
  missing     xms_edov guard
  severity    HIGH (identity trust, cross-tenant impact)
  reference   GHSA-ffp4-94w6-vfgv (sibling case)

Scanned 1 file. 1 PTB-unsafe site. See docs/METHODOLOGY.md.
```

---

## What's public vs what's retained

| Layer | Public (this repo) | Retained (NEXUS Zone) |
|---|---|---|
| Methodology spec | ✅ full | — |
| Rule engine core | ✅ 8 providers × 1 claim | expanded to 20+ providers × multi-claim |
| Dictionary | ✅ 8 verified rows | 24+ including non-public evidence |
| Call-graph propagation | one-hop | multi-hop with sink-sensitivity |
| Semantic sibling fallback | — | ML-embedding fallback |
| Case-study harness | ✅ Clerk + Stytch (public branches) | multi-target campaign engine |

---

## Case studies

See `case_studies/`:

- `clerk.md` — Clerk `clerkinc/javascript` audit
- `stytch.md` — Stytch `stytchauth/stytch-node` audit

Each case study is comment-first on the vendor's security track
before any detail lands in this repo. We do not publish specifics
of unfixed findings.

---

## Methodology paper

[`docs/METHODOLOGY.md`](docs/METHODOLOGY.md) is the normative
reference. A longer write-up targeting an academic venue is
tracked at [`identity-trust-paper`](https://github.com/61465/identity-trust-paper) (private
during peer review).

---

## License

MIT. See [`LICENSE`](LICENSE).

The retained research artifact is governed under a separate NEXUS
Zone commercial license. Contact the author for licensing of the
expanded dictionary and multi-hop propagation.
