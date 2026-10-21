"""Behavior tests for the file-level code scanner."""

from __future__ import annotations

from pathlib import Path

import pytest

from identity_trust_hunt.code_scanner import (
    DEFAULT_EXTENSIONS,
    file_contains_any,
    iter_target_files,
    scan_for_claim_access,
)


@pytest.fixture
def sample_tree(tmp_path: Path) -> Path:
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "azure.ts").write_text(
        "export function azureLogin(token) {\n"
        "  const claims = decodeJwt(token);\n"
        "  const email = claims[\"email\"];\n"
        "  return linkIdentity(email);\n"
        "}\n",
        encoding="utf-8",
    )
    (tmp_path / "src" / "azure-safe.ts").write_text(
        "export function azureLoginSafe(token) {\n"
        "  const claims = decodeJwt(token);\n"
        "  if (claims.xms_edov !== \"1\") throw new Error(\"email not verified by Azure\");\n"
        "  const email = claims[\"email\"];\n"
        "  return linkIdentity(email);\n"
        "}\n",
        encoding="utf-8",
    )
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "vendored.ts").write_text(
        'const email = claims["email"];\n',
        encoding="utf-8",
    )
    (tmp_path / "src" / "README.md").write_text("# docs", encoding="utf-8")
    return tmp_path


def test_iter_target_files_skips_node_modules_and_non_source(sample_tree: Path):
    files = iter_target_files(sample_tree)
    paths = {Path(p).name for p in files}
    assert "azure.ts" in paths
    assert "azure-safe.ts" in paths
    assert "vendored.ts" not in paths  # node_modules pruned
    assert "README.md" not in paths  # not a source extension


def test_iter_target_files_respects_custom_extensions(sample_tree: Path):
    files = iter_target_files(sample_tree, extensions=(".md",))
    assert any(p.endswith("README.md") for p in files)
    assert all(not p.endswith(".ts") for p in files)


def test_scan_for_claim_access_finds_azure_email(sample_tree: Path):
    hits = scan_for_claim_access(sample_tree, ('claims["email"]',))
    paths_hit = {h.path.rsplit("/", 1)[-1] for h in hits}
    # Both azure.ts (unsafe) and azure-safe.ts (safe) have the access pattern.
    # The scanner reports both; the rule engine distinguishes them via guards.
    assert "azure.ts" in paths_hit
    assert "azure-safe.ts" in paths_hit


def test_file_contains_any_detects_present_guard(sample_tree: Path):
    safe_file = sample_tree / "src" / "azure-safe.ts"
    assert file_contains_any(str(safe_file), ("xms_edov",)) is True


def test_file_contains_any_misses_absent_guard(sample_tree: Path):
    unsafe_file = sample_tree / "src" / "azure.ts"
    assert file_contains_any(str(unsafe_file), ("xms_edov",)) is False


def test_scan_strips_line_comments():
    # A // comment that mentions the access pattern should NOT fire.
    tmp = Path(scan_for_claim_access.__module__)  # unused; keep type stable
    import tempfile

    with tempfile.TemporaryDirectory() as td:
        f = Path(td) / "commented.ts"
        f.write_text(
            '// claims["email"] in a comment should be ignored\n'
            'const safe = "no access here";\n',
            encoding="utf-8",
        )
        hits = scan_for_claim_access(td, ('claims["email"]',))
        assert hits == [], "comment-only mention must not trigger a match"
