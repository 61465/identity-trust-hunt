"""
Static code scanner for identity-trust-hunt.

Text-level, zero-execution. Walks a target directory, strips line comments
in common languages, and reports occurrences of a provider's access
patterns together with the surrounding file's guard-pattern coverage.

The scanner is intentionally conservative:
    * no AST, no language-specific parse (yet);
    * only common identity-SDK filetypes are visited by default;
    * comments and string literals are only partially excluded — this
      makes v0.1 err on the side of recall, which the rule engine's
      per-row ``fp_risk`` tier then compensates for.

The expanded scanner (AST sink-sensitivity, data-flow from JWT
decoder to consumer, taint-propagation across modules) is retained
as a NEXUS Zone artifact per the IP split in ``docs/METHODOLOGY.md``.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


# Default file extensions scanned when the caller does not override.
# Covers the common identity-SDK languages: TypeScript/JavaScript,
# Python, Go, Ruby, Java/Kotlin, C#, PHP, Rust, Swift.
DEFAULT_EXTENSIONS: tuple[str, ...] = (
    ".ts",
    ".tsx",
    ".js",
    ".jsx",
    ".mjs",
    ".cjs",
    ".py",
    ".go",
    ".rb",
    ".java",
    ".kt",
    ".kts",
    ".cs",
    ".php",
    ".rs",
    ".swift",
)

# Directory names that are never useful to scan — vendored deps,
# build output, lockfiles, VCS metadata. Keep the list short; add
# only when a case study produces measurable noise.
_EXCLUDED_DIRS: frozenset[str] = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        "node_modules",
        "vendor",
        "dist",
        "build",
        "target",
        "__pycache__",
        ".venv",
        "venv",
        ".pytest_cache",
        ".mypy_cache",
        ".next",
        ".nuxt",
        "coverage",
    }
)


# Line-comment prefixes we strip BEFORE pattern matching. Multi-line
# comment handling is out of v0.1 scope (expanded scanner handles it).
_LINE_COMMENT_PREFIXES: tuple[str, ...] = ("//", "#", "--")


# ──────────────────────────────────────────────────────────────────────
# v0.3 — Path-weight heuristic.
# Hits in test / locale / UI storybook / fixture paths are not FALSE
# positives per se — occasionally a test fixture is itself the real
# unsafe call — but they are low-signal relative to a hit in a provider
# or callback handler. v0.3 attaches a weight 0-1 to each access, and
# the rule engine multiplies baseline confidence by this weight. The
# CLI's --min-confidence flag then suppresses the long tail.
# ──────────────────────────────────────────────────────────────────────
_LOW_WEIGHT_PATH_FRAGMENTS: tuple[str, ...] = (
    # test runners — directory-and-extension-only patterns so pytest's
    # tmp_path (which creates dirs like "test_predicate_flags_...")
    # does NOT down-weight the files it stages for a scan.
    "/test/", "/tests/", "/_test/", "/__tests__/", "/spec/",
    ".test.", ".spec.", "_test.go", "_tests.rs",
    # fixtures and mocks
    "/fixtures/", "/__mocks__/", "/mocks/", "/mockdata/",
    # locale, i18n, docs, storybook
    "/locale/", "/locales/", "/i18n/", "/translations/", "/lang/",
    "/stories/", "/storybook/", "/story/",
    # demo apps that ship inside a monorepo but are not production code
    "/demo/", "/examples/", "/example/", "/sample/",
    # type definitions only (no runtime behavior)
    ".d.ts",
)

# Python test-file pattern must match an actual FILE (`test_foo.py`),
# not a directory starting with `test_`. Checked separately.
_PYTEST_FILE_RE = __import__("re").compile(r"/test_[^/]+\.py$")

# Playwright/Cypress UI test files tend to call `.primaryAction` /
# `.primaryEmail` which match our `primary` substring without being
# OAuth code. Keep them in a separate list so we weight the whole
# file-type family consistently.
_UI_TEST_HINTS: tuple[str, ...] = (
    "playwright", "cypress", ".e2e.", "e2e-spec", "e2e_test",
)


def path_weight(path: str) -> float:
    """Return a confidence multiplier in [0.1, 1.0] for a scanned path.

    Weight 1.0 means the hit sits in production code (default assumption).
    Weight < 1.0 marks the path as low-signal — the finding is still
    reported, but the rule engine downgrades confidence so operators can
    filter the long tail with ``--min-confidence 0.6``.

    v0.3 heuristic:

    * 0.3 for test / spec / mock / fixture / locale / i18n / stories
    * 0.4 for demo / example / sample monorepo apps
    * 0.3 for UI-test harness hints (playwright / cypress / e2e)
    * 0.2 for ``.d.ts`` type-only files
    * 1.0 otherwise
    """
    p = path.lower().replace("\\", "/")
    for hint in _UI_TEST_HINTS:
        if hint in p:
            return 0.3
    if _PYTEST_FILE_RE.search(p):
        return 0.3
    for fragment in _LOW_WEIGHT_PATH_FRAGMENTS:
        if fragment in p:
            if fragment in ("/demo/", "/examples/", "/example/", "/sample/"):
                return 0.4
            if fragment == ".d.ts":
                return 0.2
            return 0.3
    return 1.0


@dataclass(frozen=True)
class ClaimAccess:
    """A single call site that reads a provider claim.

    ``line_text`` is the full non-stripped line (whitespace preserved) for
    readable reporting. ``matched_pattern`` is the exact dictionary entry
    that triggered the match.
    """

    path: str
    line_number: int
    line_text: str
    matched_pattern: str


def _is_excluded_dir(name: str) -> bool:
    return name in _EXCLUDED_DIRS or name.startswith(".")


def _strip_line_comment(line: str) -> str:
    """Remove the comment portion of a single line, naively.

    Only line-comment markers are stripped. This is sufficient for v0.1
    because our access patterns are code-shaped (``claims["email"]``) and
    almost never appear verbatim in prose. False positives from docstrings
    and inline comments are suppressed by the rule engine's guard check:
    a documentation comment that mentions ``claims["email"]`` almost
    always sits in a file that also includes the appropriate guard.
    """
    for prefix in _LINE_COMMENT_PREFIXES:
        idx = line.find(prefix)
        if idx != -1:
            # Not inside a string literal in the naive view — accept the cut.
            return line[:idx]
    return line


def iter_target_files(
    root: Path | str,
    extensions: Iterable[str] = DEFAULT_EXTENSIONS,
) -> list[str]:
    """Enumerate scannable files under ``root``.

    Excludes vendored, build, and VCS directories; filters by extension.
    Returns absolute POSIX-style paths sorted for stable reporting.
    """
    root_path = Path(root).resolve()
    ext_set = {e.lower() for e in extensions}
    results: list[str] = []
    for dirpath, dirnames, filenames in os.walk(root_path):
        # Prune excluded directories in-place for os.walk.
        dirnames[:] = [d for d in dirnames if not _is_excluded_dir(d)]
        for name in filenames:
            ext = os.path.splitext(name)[1].lower()
            if ext not in ext_set:
                continue
            full = os.path.join(dirpath, name)
            results.append(full.replace("\\", "/"))
    results.sort()
    return results


def scan_for_claim_access(
    target_root: Path | str,
    access_patterns: Iterable[str],
    *,
    extensions: Iterable[str] = DEFAULT_EXTENSIONS,
) -> list[ClaimAccess]:
    """Return every line in ``target_root`` that matches one of ``access_patterns``.

    The caller supplies the patterns (usually from a
    :class:`identity_trust_hunt.providers.ClaimContract`). Each match is
    reported with the full non-stripped line so reviewers can read context
    without re-opening the file.
    """
    patterns = tuple(access_patterns)
    if not patterns:
        return []

    found: list[ClaimAccess] = []
    for path in iter_target_files(target_root, extensions=extensions):
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                for line_number, raw in enumerate(fh, start=1):
                    stripped_of_comment = _strip_line_comment(raw)
                    for pattern in patterns:
                        if pattern in stripped_of_comment:
                            found.append(
                                ClaimAccess(
                                    path=path,
                                    line_number=line_number,
                                    line_text=raw.rstrip("\n"),
                                    matched_pattern=pattern,
                                )
                            )
                            break
        except OSError:
            # Unreadable file — skip silently; the caller sees it missing
            # from the list rather than aborting the whole scan.
            continue
    return found


def line_contains_any(line_text: str, needles: Iterable[str]) -> bool:
    """Return True if ``line_text`` contains any of ``needles``.

    Used by the v0.2 rule engine for the "line" guard scope — the
    arrow-function predicate case (`.find((e) => e.primary && e.verified)`)
    where the required guard must live INSIDE the same statement as the
    access, not merely somewhere in the file. File-scope guards wave
    through code where the guard sits a thousand lines away in a dead
    branch; line-scope guards catch the real inline unsafe reads.
    """
    needle_list = tuple(needles)
    if not needle_list:
        return False
    return any(n in line_text for n in needle_list)


def file_contains_any(path: str, needles: Iterable[str]) -> bool:
    """Return True if the file at ``path`` contains any of ``needles``.

    Reads the whole file as text once. Used by the rule engine to check
    whether a per-contract required-guard pattern is present in the same
    file as the access site.
    """
    needle_list = tuple(needles)
    if not needle_list:
        return False
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            content = fh.read()
    except OSError:
        return False
    return any(n in content for n in needle_list)
