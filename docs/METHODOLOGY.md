# PTB Framework

**Provider Trust Boundary auditing — framework specification v1.0**

Author: Abdalrahman Mohamed, NEXUS Zone Research
Correspondence: `abdarahman10555@gmail.com`
First applications: `GHSA-ffp4-94w6-vfgv` (Supabase, 2026-10-14), `GHSA-2gvh-5vh3-m2rp` (Hanko, 2026-10-14) — both CVSS 9.8 Critical, both the same Microsoft Azure `xms_edov` miss ancestor.

---

## Abstract

PTB is a framework for discovering consumer-side trust-boundary bugs in software that integrates social-login identity providers. The framework exploits a structural observation about social-login integrations at scale: each identity provider ships a *semantic contract* for the claims it returns, and consumer codebases frequently read a claim WITHOUT applying the provider's required verification steps. The result is a well-defined class of vulnerabilities — of which `nOAuth` (Descope, 2024) is the most-publicized instance — that spans Microsoft Azure, Apple Sign in with Apple, Google OIDC, Facebook Limited Login, GitHub OAuth, Discord OAuth, LinkedIn OIDC, and Twitter/X OAuth 2.0.

PTB formalizes this observation as a per-provider predicate — a deterministic, auditable discovery rule — and ships a reference implementation that evaluates the predicate over a target codebase.

---

## 1. The PTB predicate

### 1.1 Formal statement

Let `W` be a target software system that integrates one or more identity providers. Define:

- `P` = the set of identity providers `W` integrates with.
- `K(p)` for `p ∈ P` = the set of claims consumer code reads from `p`.
- `V(p, k)` = the *semantic contract* for provider `p`'s claim `k` — the set of verification steps the provider's own documentation (or a published advisory / CVE / talk) requires a consumer to perform before trusting `k`.
- `C` = the set of call sites in `W` that read any claim.
- `guards(c)` for `c ∈ C` = the set of verification steps observable in `c`'s enclosing scope.

**The PTB predicate**. For any call site `c` that reads claim `k` from provider `p`:

```
c is PTB-unsafe ⟺ ∃ v ∈ V(p, k) such that v ∉ guards(c)
```

### 1.2 Proof sketch

By construction of `V(p, k)`, the provider has published a semantic contract that `k` is trustable ONLY after each `v ∈ V(p, k)` is applied. If some `v` is absent from `guards(c)`, then `c` consumes `k` under a weaker contract than the provider guarantees. By the definition of trust-boundary violations, the gap is an attacker-controllable surface for whatever asset `k` gates (identity, account linking, authorization). ∎

### 1.3 Scope — what PTB is NOT

| In scope | Out of scope |
|---|---|
| Consumer-side missing guards | Provider-side bugs (treat as upstream) |
| Static, zero-execution analysis | Dynamic / runtime exploitation |
| Per-provider semantic contracts | Generic OAuth bugs (redirect-URI, PKCE omission, CSRF, scope escalation, open-redirect, token leak via referrer, session fixation) |
| Trust-contract gaps rooted in **what to verify** | Replay / revocation / refresh-token bugs (session management class) |
| Public-reference-anchored contracts | Speculative "providers should sign X" wishful contracts |

The "generic OAuth" column is explicitly out of scope because those classes already have mature taxonomies (OWASP ASVS, draft-ietf-oauth-security-topics, OWASP Top 10). PTB fills the gap where none of those taxonomies encode the *per-provider* semantic contract.

### 1.4 What makes PTB different

| Property | PTB | Generic OAuth hunting | SAST / linter rules |
|---|---|---|---|
| Signal source | Mismatch between provider's semantic contract and consumer guards | Pattern of known bug classes | Syntactic anti-patterns |
| Scope | Per-provider × claim | Protocol-wide | Language-wide |
| Mathematical foundation | ✅ Formal predicate | ❌ Checklist | ❌ Rule set |
| Deterministic | ✅ Boolean | Varies | ✅ Boolean |
| Zero-execution | ✅ Static only | Varies | ✅ |
| Automation-ready | ✅ Executable | Partial | ✅ |
| Produces vendor-citable advisories | ✅ Each row is anchored | Varies | Rarely |

PTB does NOT require running the target software, fuzzing, LLM inference against the codebase, or proprietary tools. It DOES require (a) public source, (b) a per-provider dictionary of claim contracts, and (c) an expert human reviewer for Step 4 (impact calibration, cross-tenant reach, GHSA severity scoring).

---

## 2. The six discovery steps

1. **Dictionary curation** — for each provider under scrutiny, enumerate the claims the provider's OIDC/OAuth response exposes, and transcribe the provider's semantic contract for each (as `V(p, k)`). Anchor every row to a public reference. (Teaching edition ships 8 rows; see `providers.py`.)

2. **Access-pattern enumeration** — for each `(p, k)`, enumerate the lexical patterns by which a consumer reads `k`. In TypeScript / JavaScript this is almost always of the form `claims["email"]` / `profile.email` / `payload.email`. The expanded dictionary tracks per-SDK handler variants.

3. **Guard-pattern enumeration** — for each `V(p, k)`, enumerate the lexical patterns by which a correct consumer invokes each `v`. Example: `xms_edov` for Azure email trust.

4. **Target scan** — walk the target codebase; for each file that contains any access pattern for `(p, k)`, check whether the file also contains ANY guard pattern for `V(p, k)`. If none, the file's access is PTB-unsafe at the v0.1 approximation (`guards(c) ≈ same-file guards`).

5. **Confidence baseline** — tier each contract by its per-row false-positive risk. Low-risk rows (xms_edov, Google hd, GitHub `verified`) are reported at ≥ 0.80 confidence; medium-risk rows (Apple SIWA, Discord, Twitter/X) at ≥ 0.55; high-risk rows are retained.

6. **Impact calibration** — a human reviewer maps each PTB-unsafe site to its downstream asset (identity gating, account linking, authorization), determines reach (per-tenant vs cross-tenant), and shapes the resulting GHSA / disclosure.

---

## 3. First applications

| Date | GHSA | Target | Provider × claim | Reward class |
|---|---|---|---|---|
| 2026-10-14 | `GHSA-ffp4-94w6-vfgv` | Supabase | Azure OIDC × `email` (xms_edov miss) | CVSS 9.8 Critical |
| 2026-10-14 | `GHSA-2gvh-5vh3-m2rp` | Hanko | Azure OIDC × `email` (xms_edov miss, unconditional `emailVerified=true`) | CVSS 9.8 Critical |

Both findings are the same ancestor contract; the framework was motivated by the observation that solving the Azure case ONCE should surface siblings across every integration ecosystem that treats `email` as identity.

---

## 4. IP split — what's public, what's retained

The public teaching edition (v0.1, this repository) ships enough of the framework to apply the methodology to a single provider / claim at a time. The expanded implementation is retained as a NEXUS Zone research artifact and is available under separate commercial license.

| Layer | Public | Retained |
|---|---|---|
| PTB predicate statement | ✅ | — |
| Proof sketch | ✅ | — |
| Provider dictionary | 8 rows, public-anchored | 24+ rows, non-public evidence |
| Access-pattern enumeration | lexical substrings | per-SDK AST patterns |
| Guard-pattern enumeration | lexical substrings | taint-flow from JWT decoder to sink |
| Guard-reachability | same-file approximation | control-flow + inter-procedural propagation |
| Confidence formula | tier-direct | multi-factor (sink sensitivity × reach × SDK recency) |
| Reporter | table / JSON | GHSA-draft generator |
| Case-study harness | per-target markdown | multi-target campaign engine |

Contact `abdarahman10555@gmail.com` for the retained layers under NDA.

---

## 5. Novelty

As of this document's date (2026-10-21), the author is aware of **no unified published taxonomy** that frames Microsoft Azure `xms_edov`, Apple `email_verified`, Google `hd`, Facebook Limited Login JWT, GitHub `verified`, Discord `verified`, LinkedIn (missing-field), and Twitter/X (freshness) as instances of a single class defined by a per-provider trust contract. Individual instances (notably nOAuth) are well-documented; the generalization is the contribution of PTB.

If a prior taxonomy exists and we missed it, open an issue — we will credit it in v0.2 and treat our contribution as an implementation.

---

## 6. Responsible-disclosure posture

The public dictionary covers only providers whose contracts are documented in public references (vendor docs, public CVEs/GHSAs, conference talks). Case studies that find PTB-unsafe sites at specific vendors are coordinated-disclosed through the vendor's security channel (GHSA, HackerOne, security@) **before** any specifics appear in this repository. Non-fixed findings live in `case_studies/_drafts/` and are gitignored.

This posture matches `apds-hunt`'s 90-day commitment for the first application of its methodology.
