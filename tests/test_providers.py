"""Shape tests for the public PTB provider dictionary."""

from __future__ import annotations

import pytest

from identity_trust_hunt.providers import (
    PUBLIC_PROVIDERS,
    all_slugs,
    provider_by_slug,
)


def test_eight_public_providers_ship():
    assert len(PUBLIC_PROVIDERS) == 8


def test_slugs_are_unique_and_lowercase():
    slugs = all_slugs()
    assert len(set(slugs)) == len(slugs)
    for s in slugs:
        assert s == s.lower()
        assert " " not in s


def test_every_contract_has_evidence_and_guards_and_patterns():
    for p in PUBLIC_PROVIDERS:
        assert p.contracts, f"{p.slug} has no contracts"
        for c in p.contracts:
            assert c.claim, f"{p.slug} contract missing claim"
            assert c.access_patterns, f"{p.slug}/{c.claim} missing access patterns"
            assert c.required_guards, f"{p.slug}/{c.claim} missing guards"
            assert c.fp_risk in {"low", "med", "high"}
            assert c.public_reference.strip(), f"{p.slug}/{c.claim} missing public_reference"


def test_azure_contract_mentions_xms_edov_and_known_ghsas():
    azure = provider_by_slug("azure")
    assert azure is not None
    contract = azure.contracts[0]
    assert any("xms" in g.lower() for g in contract.required_guards)
    ref = contract.public_reference.lower()
    assert "ghsa-ffp4-94w6-vfgv" in ref
    assert "ghsa-2gvh-5vh3-m2rp" in ref


def test_apple_contract_requires_both_verified_and_private_email_handling():
    apple = provider_by_slug("apple")
    assert apple is not None
    contract = apple.contracts[0]
    guards = {g.lower() for g in contract.required_guards}
    assert any("email_verified" in g or "emailverified" in g for g in guards)
    assert any("private" in g for g in guards)


def test_linkedin_contract_treats_missing_field_as_consumer_duty():
    # LinkedIn OIDC exposes no email_verified field — the guard
    # must be an explicit side-channel verification by the consumer.
    linkedin = provider_by_slug("linkedin")
    assert linkedin is not None
    contract = linkedin.contracts[0]
    guards = {g.lower() for g in contract.required_guards}
    assert any("otp" in g or "challenge" in g or "verifyemail" in g for g in guards)


def test_provider_by_slug_returns_none_for_unknown():
    assert provider_by_slug("not-a-provider") is None
