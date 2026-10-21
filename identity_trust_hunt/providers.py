"""
Public PTB provider dictionary for identity-trust-hunt v0.1.

Each :class:`Provider` ships one or more :class:`ClaimContract` entries that
spell out, for a single provider × claim, (a) how a consumer accesses the
claim, (b) which guard the provider's semantic contract requires, and
(c) the public evidence anchoring the contract.

Only rows with a *public* citation (vendor doc / public CVE / public talk)
ship here. Rows anchored on non-public evidence live in the retained
research dictionary (see ``docs/METHODOLOGY.md``, IP split).
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class ClaimContract:
    """A single provider × claim trust contract.

    Attributes
    ----------
    claim:
        Name of the claim as the consumer sees it (``email``, ``hd``,
        ``verified``). The scanner matches against this name case-sensitively.
    access_patterns:
        Textual patterns that identify a consumer READING the claim. Each
        pattern is a plain substring; the scanner reports a match when the
        pattern appears anywhere on a non-comment line of a target file.
        Patterns are deliberately conservative — the goal is a HIGH-precision
        detector, not maximum recall.
    required_guards:
        Textual patterns that must appear in the SAME file (anywhere) for
        the access to be considered PTB-safe. If none of the guards appear,
        the access is flagged.
    guard_scope:
        ``"file"`` (default — the v0.1 behavior) or ``"line"``. When
        ``"line"``, a guard pattern must appear on the SAME source line
        as the access. This catches arrow-function predicates like
        ``.find((e) => e.primary && e.verified)`` where the guard must
        live inside the statement, not merely in the enclosing file.
        File-scope misses the Auth.js case (GHSA-x3fc-mfpw-93f6) because
        the file imports GitHub types elsewhere; line-scope catches it.
    fp_risk:
        ``low`` / ``med`` / ``high`` — baseline false-positive risk when the
        detector fires with no cross-check. Expanded sink-sensitivity
        scoring is retained; v0.1 uses the tier directly.
    public_reference:
        Short label naming the public source (CVE id, GHSA id, vendor
        doc URL fragment, talk citation).
    """

    claim: str
    access_patterns: tuple[str, ...]
    required_guards: tuple[str, ...]
    fp_risk: str
    public_reference: str
    guard_scope: str = "file"


@dataclass(frozen=True)
class Provider:
    """A single identity provider under the PTB framework.

    ``slug`` is used as the CLI selector (``--provider azure``). Each
    provider holds one or more :class:`ClaimContract` rows.
    """

    slug: str
    display_name: str
    contracts: tuple[ClaimContract, ...]


# -----------------------------------------------------------------------
# Public PTB dictionary — v0.1 ships 8 provider × claim rows.
#
# Each row is anchored to a PUBLIC reference. The expanded dictionary
# (per-SDK handler patterns, multi-claim combined trust rules, locale
# variants, deprecated-flow trust gaps) is retained per the IP split.
# -----------------------------------------------------------------------
PUBLIC_PROVIDERS: tuple[Provider, ...] = (
    Provider(
        slug="azure",
        display_name="Microsoft Azure OIDC",
        contracts=(
            ClaimContract(
                claim="email",
                access_patterns=(
                    'claims["email"]',
                    "claims.email",
                    "claims.get('email')",
                    'claims.get("email")',
                    "token.email",
                    "payload.email",
                    "idTokenPayload.email",
                    "profile.email",
                ),
                required_guards=(
                    "xms_edov",
                    "xmsEdov",
                    "xms-edov",
                ),
                fp_risk="low",
                public_reference=(
                    "nOAuth (Descope 2024); GHSA-ffp4-94w6-vfgv Supabase; "
                    "GHSA-2gvh-5vh3-m2rp Hanko"
                ),
            ),
            # v0.2 — Microsoft Graph /me surface. Keycloak and Documenso
            # both consume Graph /me's `mail` field without going through
            # the id_token claim set, so the first contract above does
            # not fire. The Microsoft-specific `xms_edov` guard still
            # has to be present somewhere in the handler to pass PTB.
            ClaimContract(
                claim="mail",
                access_patterns=(
                    "graph.microsoft.com/v1.0/me",
                    "graph.microsoft.com/me",
                    'profile.get("mail")',
                    "profile.get('mail')",
                    'getJsonProperty(profile, "mail")',
                    "claims.mail",
                    'claims["mail"]',
                    "profile.mail",
                ),
                required_guards=(
                    "xms_edov",
                    "xmsEdov",
                    "xms-edov",
                ),
                fp_risk="low",
                public_reference=(
                    "Microsoft Entra ID — xms_edov semantics on Graph /me; "
                    "GHSA-hm26-jm32-3wp4 Documenso applied the same pattern"
                ),
            ),
        ),
    ),
    Provider(
        slug="apple",
        display_name="Apple Sign in with Apple",
        contracts=(
            ClaimContract(
                claim="email",
                # Narrow to Apple-specific symbols — SDK types, endpoint
                # URLs, and documented SIWA function names only.
                access_patterns=(
                    "appleid.apple.com",
                    "sign_in_with_apple",
                    "signInWithApple",
                    "AppleIDProvider",
                    "SignInWithAppleResponse",
                    "SIWAResponse",
                ),
                required_guards=(
                    "email_verified",
                    "emailVerified",
                    "is_private_email",
                    "isPrivateEmail",
                ),
                fp_risk="med",
                public_reference=(
                    "Apple Developer: 'Sign in with Apple REST API' — "
                    "`email_verified` and `is_private_email` are REQUIRED "
                    "to distinguish user-provided vs private-relay emails"
                ),
            ),
        ),
    ),
    Provider(
        slug="google",
        display_name="Google OIDC",
        contracts=(
            ClaimContract(
                claim="hd",
                access_patterns=(
                    'claims["hd"]',
                    "claims.hd",
                    "payload.hd",
                    "token.hd",
                    "idTokenPayload.hd",
                    'profile["hd"]',
                    "profile.hd",
                ),
                required_guards=(
                    "allowed_domains",
                    "allowedDomains",
                    "hosted_domain",
                    "hostedDomain",
                    "domain_whitelist",
                    "domainAllowList",
                    "domainAllowlist",
                ),
                fp_risk="low",
                public_reference=(
                    "Google Identity 'OpenID Connect': `hd` is advisory "
                    "and MUST be pinned to an allowed domain list; "
                    "blind trust = cross-tenant impersonation"
                ),
            ),
        ),
    ),
    Provider(
        slug="facebook",
        display_name="Facebook Limited Login",
        contracts=(
            ClaimContract(
                claim="email",
                access_patterns=(
                    "limited_login",
                    "limitedLogin",
                    "LimitedLoginJWT",
                    "facebookLimitedLogin",
                ),
                required_guards=(
                    "email_verified",
                    "emailVerified",
                    "verify_jwt",
                    "verifyJwt",
                    "jwks",
                ),
                fp_risk="med",
                public_reference=(
                    "Meta Developer Docs: Limited Login (iOS/Android) "
                    "returns a JWT; verifier skew vs classic Login is a "
                    "documented migration hazard"
                ),
            ),
        ),
    ),
    Provider(
        slug="github",
        display_name="GitHub OAuth",
        contracts=(
            ClaimContract(
                claim="email",
                access_patterns=(
                    "api.github.com/user",
                    "user/emails",
                    '"primary": true',
                    '"primary":true',
                    "primary: true",
                    "e.primary",
                ),
                required_guards=(
                    '"verified": true',
                    '"verified":true',
                    "verified: true",
                    "e.verified",
                    "email.verified",
                ),
                fp_risk="low",
                public_reference=(
                    "GitHub REST docs: /user/emails returns objects with "
                    "both `primary` and `verified`; consumers must gate "
                    "trust on `verified`, not `primary`"
                ),
            ),
            # v0.2 — arrow-function predicate on `.find()` that filters by
            # `primary` without ANDing `verified`. This is the Auth.js
            # bug class (GHSA-x3fc-mfpw-93f6): the file imports GitHub
            # SDK types and legitimately uses `.verified` elsewhere, so
            # file-scope guard checks let the unsafe statement pass. The
            # unsafe check must live on the SAME LINE as the access.
            ClaimContract(
                claim="primary",
                access_patterns=(
                    ".find((e) => e.primary)",
                    ".find(e => e.primary)",
                    ".find((e)=>e.primary)",
                    ".find(e=>e.primary)",
                    ".filter((e) => e.primary)",
                    ".filter(e => e.primary)",
                    ".filter((e)=>e.primary)",
                ),
                required_guards=(
                    "e.verified",
                    "&& e.verified",
                    "&& verified",
                ),
                fp_risk="low",
                guard_scope="line",
                public_reference=(
                    "GHSA-x3fc-mfpw-93f6 Auth.js: find((e) => e.primary) picks "
                    "unverified secondaries; guard must AND `e.verified`"
                ),
            ),
        ),
    ),
    Provider(
        slug="discord",
        display_name="Discord OAuth",
        contracts=(
            ClaimContract(
                claim="verified",
                # Narrow to Discord-specific endpoints and SDK types.
                access_patterns=(
                    "discord.com/api/users/@me",
                    "discordapp.com/api/users/@me",
                    "DiscordUser",
                    "DiscordAPIResponse",
                ),
                required_guards=(
                    "verified === true",
                    "verified == true",
                    "verified is True",
                    "verified: true",
                ),
                fp_risk="med",
                public_reference=(
                    "Discord Developer Portal: /users/@me `verified` is "
                    "nullable; some SDKs coerce `undefined` to truthy"
                ),
            ),
        ),
    ),
    Provider(
        slug="linkedin",
        display_name="LinkedIn OpenID Connect",
        contracts=(
            ClaimContract(
                claim="email",
                # Narrow to LinkedIn-specific endpoints + scope strings.
                access_patterns=(
                    "api.linkedin.com/v2/emailAddress",
                    "api.linkedin.com/v2/me",
                    "www.linkedin.com/oauth/v2/accessToken",
                    "r_emailaddress",
                    "r_liteprofile",
                ),
                required_guards=(
                    # LinkedIn OIDC publishes no email_verified field —
                    # the correct guard is a SEPARATE email challenge
                    # (OTP, link). We accept any of these as "the
                    # developer did their own verification".
                    "sendOtp",
                    "send_otp",
                    "emailChallenge",
                    "email_challenge",
                    "verifyEmail",
                    "verify_email",
                ),
                fp_risk="low",
                public_reference=(
                    "LinkedIn OpenID Connect reference: no `email_verified` "
                    "claim is exposed; consumers that treat the email as "
                    "verified-by-provider are PTB-unsafe"
                ),
            ),
        ),
    ),
    Provider(
        slug="twitter",
        display_name="Twitter / X OAuth 2.0",
        contracts=(
            ClaimContract(
                claim="email",
                # Narrow to Twitter/X-specific API endpoints.
                access_patterns=(
                    "api.twitter.com/2/users/me",
                    "api.x.com/2/users/me",
                    "api.twitter.com/1.1/account/verify_credentials",
                ),
                required_guards=(
                    "refreshEmail",
                    "refresh_email",
                    "revalidateEmail",
                    "revalidate_email",
                    "updateUserEmail",
                    "verifyEmail",
                ),
                fp_risk="med",
                public_reference=(
                    "Twitter/X Developer Docs: email on /users/me can be "
                    "stale relative to the token; consumers must revalidate "
                    "before trust-gating on it"
                ),
            ),
        ),
    ),
)


def provider_by_slug(slug: str) -> Provider | None:
    """Return the public :class:`Provider` with the given slug, or ``None``."""
    for provider in PUBLIC_PROVIDERS:
        if provider.slug == slug:
            return provider
    return None


def all_slugs() -> tuple[str, ...]:
    """Return the slugs of all v0.1 public providers in display order."""
    return tuple(p.slug for p in PUBLIC_PROVIDERS)
