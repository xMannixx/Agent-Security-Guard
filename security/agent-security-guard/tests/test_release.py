"""One version, said the same way everywhere.

A release that bumps the number in one file and not in another, or leaves the
README describing the release before, is how readers end up with the wrong
idea of what they are running. Skipped where the repository around the package
is not there (an installed copy).
"""

import re
from pathlib import Path

import pytest

import agent_security_guard

REPO_ROOT = Path(__file__).resolve().parents[3]
VERSION = agent_security_guard.__version__

pytestmark = pytest.mark.skipif(
    not (REPO_ROOT / "pyproject.toml").is_file(), reason="not inside the repository"
)


def _text(*parts):
    return REPO_ROOT.joinpath(*parts).read_text(encoding="utf-8")


def _first(pattern, text):
    found = re.search(pattern, text, re.MULTILINE)
    assert found, pattern
    return found.group(1)


def test_version_is_the_same_everywhere():
    assert _first(r'^version = "([^"]+)"', _text("pyproject.toml")) == VERSION
    assert _first(r"^version: (\S+)", _text("plugin", "plugin.yaml")) == VERSION
    assert _first(r"^version: (\S+)", _text("security", "agent-security-guard", "SKILL.md")) == VERSION


def test_changelog_has_an_entry_for_the_version():
    released = _first(r"^## \[(\d[^\]]*)\]", _text("CHANGELOG.md"))
    assert released == VERSION, "the newest released entry in CHANGELOG.md is for another version"


def test_readme_and_skill_describe_the_version():
    for parts in (("README.md",), ("security", "agent-security-guard", "SKILL.md"), ("ROADMAP.md",)):
        text = _text(*parts)
        assert VERSION in text, f"{parts[-1]} does not mention {VERSION}"


def test_readme_status_starts_with_the_current_version():
    status = _text("README.md").split("## Status & roadmap", 1)[1]
    assert status.lstrip().startswith(f"v{VERSION}")
