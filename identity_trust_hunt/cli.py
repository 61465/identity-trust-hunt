"""CLI entry point for identity-trust-hunt."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .providers import PUBLIC_PROVIDERS, all_slugs
from .reporter import to_json, to_table
from .rule_engine import scan_target


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="identity-trust-hunt",
        description=(
            "Provider Trust Boundary auditor — scan a codebase for consumer-side "
            "trust gaps against per-provider semantic contracts (nOAuth and siblings)."
        ),
        epilog=(
            "This is the public v0.1 teaching edition. See docs/METHODOLOGY.md for "
            "the IP split and NDA path for the full implementation."
        ),
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan = subparsers.add_parser(
        "scan",
        help="Scan a target directory for PTB-unsafe call sites.",
    )
    scan.add_argument(
        "target",
        type=Path,
        help="Path to the target source tree to scan.",
    )
    scan.add_argument(
        "--provider",
        action="append",
        default=[],
        choices=all_slugs(),
        help=(
            "Restrict the scan to a specific provider (may be repeated). "
            "Defaults to all public providers."
        ),
    )
    scan.add_argument(
        "--claim",
        action="append",
        default=[],
        help=(
            "Restrict the scan to a specific claim (e.g. 'email', 'hd'). "
            "May be repeated. Defaults to all claims the selected providers ship."
        ),
    )
    scan.add_argument(
        "--format",
        choices=("table", "json"),
        default="table",
        help="Output format (default: table).",
    )
    scan.add_argument(
        "--min-confidence",
        type=float,
        default=0.0,
        metavar="FLOAT",
        help="Suppress findings whose baseline confidence is below this threshold.",
    )

    subparsers.add_parser(
        "list-providers",
        help="Print the public provider dictionary and exit.",
    )

    parser.add_argument(
        "--version",
        action="version",
        version=f"identity-trust-hunt {__version__}",
    )
    return parser


def _list_providers() -> int:
    for provider in PUBLIC_PROVIDERS:
        print(f"[{provider.slug}] {provider.display_name}")
        for c in provider.contracts:
            print(f"  claim={c.claim!r}  fp_risk={c.fp_risk}  ref={c.public_reference}")
            print(f"    required_guards: {list(c.required_guards)}")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)

    if args.command == "list-providers":
        return _list_providers()

    if args.command == "scan":
        target: Path = args.target
        if not target.exists():
            print(f"identity-trust-hunt: target does not exist: {target}", file=sys.stderr)
            return 2
        if not target.is_dir():
            print(f"identity-trust-hunt: target must be a directory: {target}", file=sys.stderr)
            return 2

        findings = scan_target(
            target,
            only_providers=args.provider,
            only_claims=args.claim,
        )
        if args.min_confidence > 0:
            findings = [f for f in findings if f.confidence >= args.min_confidence]

        if args.format == "json":
            print(to_json(findings))
        else:
            print(to_table(findings))
        return 0 if findings else 1

    return 2  # unreachable; argparse already enforces command presence


if __name__ == "__main__":
    sys.exit(main())
