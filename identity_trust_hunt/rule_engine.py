"""
The PTB predicate — core discovery engine for identity-trust-hunt.

From the methodology spec (``docs/METHODOLOGY.md``):

    For a call site c in system W that consumes claim k from provider p:
        c is PTB-unsafe ⟺ ∃ v ∈ V(p, k) such that v ∉ guards(c)

Where ``V(p, k)`` is the provider's semantic contract (the set of
verifications the consumer MUST do) and ``guards(c)`` is the set of
verifications actually visible in c's enclosing scope.

v0.1 approximates ``guards(c)`` as *same-file guards* — the expanded
engine (per-function scope, cross-module taint, call-graph propagation)
is retained as a NEXUS Zone artifact per the IP split documented in
``docs/METHODOLOGY.md``.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from .code_scanner import ClaimAccess, file_contains_any, scan_for_claim_access
from .providers import PUBLIC_PROVIDERS, ClaimContract, Provider


@dataclass(frozen=True)
class PTBFinding:
    """A single Provider Trust Boundary unsafe call site.

    - ``provider`` and ``claim`` identify which trust contract was
      violated.
    - ``access`` carries the file / line / exact match that triggered
      the finding.
    - ``missing_guards`` lists the required-guard patterns the enclosing
      file lacks (none of them appear anywhere in the file).
    - ``confidence`` is a shallow 0.0-1.0 score. The expanded formula
      (sink-sensitivity, data-flow from decoder to consumer, co-location
      with provider SDK import) is retained per the IP split.
    """

    provider_slug: str
    provider_display_name: str
    claim: str
    access: ClaimAccess
    missing_guards: tuple[str, ...]
    confidence: float
    rationale: str
    public_reference: str


def _baseline_confidence(contract: ClaimContract) -> float:
    """Shallow confidence scorer; see :class:`PTBFinding` docstring."""
    return {"low": 0.80, "med": 0.55, "high": 0.30}.get(contract.fp_risk, 0.30)


def _evaluate_contract(
    target_root: Path | str,
    provider: Provider,
    contract: ClaimContract,
) -> list[PTBFinding]:
    """Evaluate one contract and return every PTB-unsafe access.

    An access is UNSAFE when the file it sits in contains the access
    pattern but contains NONE of the required-guard patterns anywhere in
    its content. That matches the v0.1 approximation of
    ``guards(c) = same-file guards``.
    """
    accesses = scan_for_claim_access(target_root, contract.access_patterns)
    if not accesses:
        return []

    # Precompute guard presence per file so we don't re-read a file for
    # every access it contains.
    guard_cache: dict[str, bool] = {}

    def has_guard(path: str) -> bool:
        cached = guard_cache.get(path)
        if cached is not None:
            return cached
        resolved = file_contains_any(path, contract.required_guards)
        guard_cache[path] = resolved
        return resolved

    findings: list[PTBFinding] = []
    for access in accesses:
        if has_guard(access.path):
            # Guard present somewhere in the same file: v0.1 trusts it.
            # The expanded engine checks guard-reaches-this-site via
            # control flow and taint — retained.
            continue
        confidence = _baseline_confidence(contract)
        rationale = (
            f"PTB predicate: file {access.path!r} consumes "
            f"{contract.claim!r} from {provider.display_name} "
            f"(line {access.line_number}, pattern {access.matched_pattern!r}) "
            f"without any of the required guards "
            f"{list(contract.required_guards)}."
        )
        findings.append(
            PTBFinding(
                provider_slug=provider.slug,
                provider_display_name=provider.display_name,
                claim=contract.claim,
                access=access,
                missing_guards=tuple(contract.required_guards),
                confidence=confidence,
                rationale=rationale,
                public_reference=contract.public_reference,
            )
        )
    return findings


def scan_target(
    target_root: Path | str,
    *,
    providers: Iterable[Provider] = PUBLIC_PROVIDERS,
    only_providers: Iterable[str] = (),
    only_claims: Iterable[str] = (),
) -> list[PTBFinding]:
    """Evaluate the PTB predicate across every requested provider.

    ``only_providers`` and ``only_claims`` are optional allow-lists keyed
    on provider slug and claim name respectively. Empty allow-lists mean
    "no restriction".

    Findings are returned sorted by confidence (desc) so a reviewer sees
    the strongest-signal call sites first.
    """
    provider_filter = {s for s in only_providers}
    claim_filter = {c for c in only_claims}

    findings: list[PTBFinding] = []
    for provider in providers:
        if provider_filter and provider.slug not in provider_filter:
            continue
        for contract in provider.contracts:
            if claim_filter and contract.claim not in claim_filter:
                continue
            findings.extend(_evaluate_contract(target_root, provider, contract))

    findings.sort(key=lambda f: f.confidence, reverse=True)
    return findings
