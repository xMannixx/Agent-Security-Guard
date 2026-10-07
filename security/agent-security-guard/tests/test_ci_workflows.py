"""The CI workflows hold to a few rules that are easy to lose in an edit.

They run with a token for this repository and install code from elsewhere, so
what they may do and what exactly they run is part of the project's security.
These tests read the workflow files as text; they are skipped where the
repository around the package is not there (an installed copy).
"""

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
WORKFLOWS = sorted((REPO_ROOT / ".github" / "workflows").glob("*.y*ml"))

pytestmark = pytest.mark.skipif(not WORKFLOWS, reason="not inside the repository")

_USES = re.compile(r"^\s*(?:-\s*)?uses:\s*(\S+)(.*)$", re.MULTILINE)
_PINNED = re.compile(r"^[\w.-]+/[\w./-]+@[0-9a-f]{40}$")


def _text(path):
    return path.read_text(encoding="utf-8")


@pytest.mark.parametrize("workflow", WORKFLOWS, ids=lambda path: path.name)
def test_every_action_is_pinned_to_a_commit(workflow):
    # A tag such as `v7` can be moved to other code by whoever controls the
    # action's repository. A commit cannot.
    used = _USES.findall(_text(workflow))
    assert used, "no actions found; the pattern above needs a look"
    for action, rest in used:
        assert _PINNED.match(action), f"{action} is not pinned to a full commit hash"
        assert re.search(r"#\s*v\d", rest), f"{action} does not say which version the hash is"


@pytest.mark.parametrize("workflow", WORKFLOWS, ids=lambda path: path.name)
def test_token_is_read_only_unless_a_job_says_otherwise(workflow):
    text = _text(workflow)
    top_level = re.search(r"^permissions:\n((?:[ \t]+\S.*\n)+)", text, re.MULTILINE)
    assert top_level, "no top-level `permissions:` block"
    assert top_level.group(1).split() == ["contents:", "read"]
    assert "write-all" not in text
    for granted in re.findall(r"^\s+([\w-]+):\s*write\b", text, re.MULTILINE):
        assert granted == "security-events", f"a job grants {granted}: write"


@pytest.mark.parametrize("workflow", WORKFLOWS, ids=lambda path: path.name)
def test_checkout_does_not_leave_the_token_in_the_working_copy(workflow):
    text = _text(workflow)
    assert text.count("actions/checkout@") == text.count("persist-credentials: false")


@pytest.mark.parametrize("workflow", WORKFLOWS, ids=lambda path: path.name)
def test_nothing_is_installed_without_hashes(workflow):
    for line in _text(workflow).splitlines():
        if re.search(r"\bpip3?\s+install\b", line):
            assert "--require-hashes" in line, line.strip()
            assert "--upgrade" not in line, line.strip()


@pytest.mark.parametrize("workflow", WORKFLOWS, ids=lambda path: path.name)
def test_jobs_cannot_run_for_hours(workflow):
    # A job once hung in its test step; the default limit is six hours.
    text = _text(workflow)
    assert text.count("runs-on:") == text.count("timeout-minutes:")


@pytest.mark.parametrize("workflow", WORKFLOWS, ids=lambda path: path.name)
def test_workflows_do_not_run_with_the_base_repositorys_secrets_on_foreign_code(workflow):
    assert "pull_request_target" not in _text(workflow)


def test_pinned_requirements_carry_a_hash_for_every_package():
    lines = _text(REPO_ROOT / "requirements-ci.txt").splitlines()
    pins = [line for line in lines if re.match(r"^[A-Za-z0-9_.-]+==", line)]
    assert pins and any(line.startswith("pytest==") for line in pins)
    for index, line in enumerate(lines):
        if line in pins:
            assert lines[index + 1].lstrip().startswith("--hash=sha256:"), line


def test_static_analysis_covers_the_code_and_the_workflows():
    text = _text(REPO_ROOT / ".github" / "workflows" / "codeql.yml")
    assert "github/codeql-action/init@" in text and "github/codeql-action/analyze@" in text
    assert re.search(r"language:\s*\[python,\s*actions\]", text)
