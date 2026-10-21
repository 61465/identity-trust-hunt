"""Formatting for identity-trust-hunt findings."""

from __future__ import annotations

import json
from dataclasses import asdict
from typing import Iterable

from .rule_engine import PTBFinding


def to_json(findings: Iterable[PTBFinding]) -> str:
    """Serialize findings as a stable, machine-readable JSON array."""
    payload = []
    for f in findings:
        payload.append(
            {
                "provider": {"slug": f.provider_slug, "display_name": f.provider_display_name},
                "claim": f.claim,
                "access": asdict(f.access),
                "missing_guards": list(f.missing_guards),
                "confidence": round(f.confidence, 3),
                "rationale": f.rationale,
                "public_reference": f.public_reference,
            }
        )
    return json.dumps(payload, indent=2, sort_keys=False)


def to_table(findings: Iterable[PTBFinding]) -> str:
    """Render findings as a plain-text table suitable for a terminal."""
    rows = list(findings)
    if not rows:
        return (
            "No PTB findings. Every claim access in the target has at least "
            "one of its provider's required guards present in the same file."
        )

    header = (
        f"{'CONF':>5} | {'PROVIDER':<28} | {'CLAIM':<10} | {'LOCATION':<60}"
    )
    separator = "-" * len(header)
    lines = [header, separator]
    for f in rows:
        loc = f"{f.access.path}:{f.access.line_number}"
        # Keep the filename visible on long paths — truncate from the left.
        loc_rendered = loc if len(loc) <= 60 else "..." + loc[-57:]
        lines.append(
            f"{f.confidence:>5.2f} | {f.provider_display_name[:28]:<28} | "
            f"{f.claim[:10]:<10} | {loc_rendered:<60}"
        )
    lines.append("")
    lines.append(
        "PTB predicate — each row is a claim access that lacks the provider's required guard."
    )
    lines.append("Review each candidate against the vendor's semantic contract (public_reference in JSON output).")
    return "\n".join(lines)
