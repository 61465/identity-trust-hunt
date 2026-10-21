"""Smoke tests for the CLI entry point."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from identity_trust_hunt.cli import main


def test_list_providers_prints_eight_rows(capsys):
    rc = main(["list-providers"])
    assert rc == 0
    output = capsys.readouterr().out
    # Count the lines that start with "[" — one per provider.
    bracketed = [line for line in output.splitlines() if line.startswith("[")]
    assert len(bracketed) == 8


def test_scan_reports_azure_finding_in_table(tmp_path: Path, capsys):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "a.ts").write_text(
        'const email = claims["email"];\n', encoding="utf-8"
    )
    rc = main(["scan", str(tmp_path), "--provider", "azure"])
    assert rc == 0  # findings present
    captured = capsys.readouterr().out
    assert "Microsoft Azure OIDC" in captured
    assert "a.ts" in captured
    assert "email" in captured


def test_scan_returns_1_when_no_findings(tmp_path: Path, capsys):
    (tmp_path / "clean.ts").write_text("export const x = 1;\n", encoding="utf-8")
    rc = main(["scan", str(tmp_path)])
    assert rc == 1  # no findings


def test_scan_json_format_is_valid_json(tmp_path: Path, capsys):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "a.ts").write_text(
        'const email = claims["email"];\n', encoding="utf-8"
    )
    rc = main(["scan", str(tmp_path), "--format", "json"])
    assert rc == 0
    captured = capsys.readouterr().out
    payload = json.loads(captured)
    assert isinstance(payload, list)
    assert payload[0]["provider"]["slug"] == "azure"
    assert payload[0]["claim"] == "email"
