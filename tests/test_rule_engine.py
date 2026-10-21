"""End-to-end tests for the PTB predicate across the full pipeline."""

from __future__ import annotations

from pathlib import Path

import pytest

from identity_trust_hunt.rule_engine import scan_target


@pytest.fixture
def azure_unsafe_project(tmp_path: Path) -> Path:
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "handler.ts").write_text(
        "export async function handle(idToken: string) {\n"
        "  const claims = decodeJwt(idToken);\n"
        "  const email = claims[\"email\"];\n"
        "  await linkIdentity(email);\n"
        "}\n",
        encoding="utf-8",
    )
    return tmp_path


@pytest.fixture
def azure_safe_project(tmp_path: Path) -> Path:
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "handler.ts").write_text(
        "export async function handle(idToken: string) {\n"
        "  const claims = decodeJwt(idToken);\n"
        "  if (claims.xms_edov !== \"1\") {\n"
        "    throw new Error(\"Azure did not verify email ownership\");\n"
        "  }\n"
        "  const email = claims[\"email\"];\n"
        "  await linkIdentity(email);\n"
        "}\n",
        encoding="utf-8",
    )
    return tmp_path


def test_predicate_flags_azure_xms_edov_miss(azure_unsafe_project: Path):
    findings = scan_target(azure_unsafe_project, only_providers=("azure",))
    assert len(findings) == 1
    f = findings[0]
    assert f.provider_slug == "azure"
    assert f.claim == "email"
    assert f.access.path.endswith("handler.ts")
    assert "xms_edov" in f.missing_guards
    assert f.confidence >= 0.80  # low fp_risk tier
    assert "xms_edov" in f.rationale


def test_predicate_silent_when_guard_present(azure_safe_project: Path):
    findings = scan_target(azure_safe_project, only_providers=("azure",))
    assert findings == []


def test_claim_filter_narrows_results(azure_unsafe_project: Path):
    assert scan_target(azure_unsafe_project, only_claims=("hd",)) == []
    assert scan_target(azure_unsafe_project, only_claims=("email",))


def test_github_requires_verified_not_just_primary(tmp_path: Path):
    (tmp_path / "sdk").mkdir()
    (tmp_path / "sdk" / "github.ts").write_text(
        "const emails = await fetch('https://api.github.com/user/emails');\n"
        "const primary = emails.find(e => e.primary === true);\n"
        "await signup(primary.email);\n",
        encoding="utf-8",
    )
    findings = scan_target(tmp_path, only_providers=("github",))
    assert len(findings) >= 1
    assert findings[0].provider_slug == "github"


def test_github_safe_when_verified_check_present(tmp_path: Path):
    (tmp_path / "sdk").mkdir()
    (tmp_path / "sdk" / "github.ts").write_text(
        "const emails = await fetch('https://api.github.com/user/emails');\n"
        "const safe = emails.find(e => e.primary === true && e.verified === true);\n"
        "await signup(safe.email);\n",
        encoding="utf-8",
    )
    findings = scan_target(tmp_path, only_providers=("github",))
    assert findings == []


def test_findings_sort_by_confidence_descending(tmp_path: Path):
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    (tmp_path / "a" / "azure.ts").write_text(
        'const email = claims["email"];\n', encoding="utf-8"
    )
    (tmp_path / "b" / "discord.ts").write_text(
        "import { DiscordProvider } from 'next-auth/providers/discord';\n",
        encoding="utf-8",
    )
    findings = scan_target(tmp_path)
    # Azure (fp_risk=low, 0.80) must come before Discord (fp_risk=med, 0.55).
    confidences = [f.confidence for f in findings]
    assert confidences == sorted(confidences, reverse=True)


def test_empty_project_returns_no_findings(tmp_path: Path):
    (tmp_path / "empty.ts").write_text("export const x = 1;\n", encoding="utf-8")
    assert scan_target(tmp_path) == []
