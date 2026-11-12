"""Hostile text must not stall the agent.

Web results, model-written file payloads and user messages are all shaped by
somebody else. A regex that backtracks on them turns a page into a pause of
seconds to minutes. Each pattern here took seconds on 20 KB before it was made
linear; each must now stay well under 50 ms, on one line and across many.
"""

import time

import pytest

from agent_security_guard import detect_no_write_scope, is_short_confirmation
from agent_security_guard.actions import AgentAction
from agent_security_guard.patterns import EXECUTABLE_PATTERNS, scan_patterns
from agent_security_guard.policy import _PATCH_PATH, _written_paths
from agent_security_guard.scanner import scan_input

N = 20_000
BUDGET_SECONDS = 0.05


def _fastest(fn, text, runs=3):
    best = float("inf")
    for _ in range(runs):
        start = time.perf_counter()
        fn(text)
        best = min(best, time.perf_counter() - start)
    return best


def _assert_fast(fn, text):
    assert len(text) >= N
    took = _fastest(fn, text)
    assert took < BUDGET_SECONDS, f"{took * 1000:.0f} ms on {text[:40]!r}..."


# --- rm -r in content (scanned on every web/search/browser result) ----------

RM_INPUTS = {
    "flags, single line": "rm -" + "r" * N + "1",
    "flags, many lines": ("rm -" + "r" * 400 + "1\n") * 60,
    "spaces": "rm" + " " * N + "x",
    "repeated": "rm -r1 " * (N // 6),
}


@pytest.mark.parametrize("text", RM_INPUTS.values(), ids=RM_INPUTS.keys())
def test_rm_pattern_is_linear(text):
    _assert_fast(lambda t: scan_patterns(t, EXECUTABLE_PATTERNS), text)


@pytest.mark.parametrize("text", RM_INPUTS.values(), ids=RM_INPUTS.keys())
def test_scanning_a_hostile_page_is_fast(text):
    _assert_fast(lambda t: scan_input(t, source="web", channel="web_extract"), text)


@pytest.mark.parametrize("command", ["rm -r x", "rm -rf /", "rm -fr ~", "RM -Rv dir", "rm -r1"])
def test_rm_with_r_is_still_found(command):
    assert "rm_rf" in scan_patterns(command, EXECUTABLE_PATTERNS)


@pytest.mark.parametrize("command", ["rm file", "rm -f file", "rm -i x", "firm -r"])
def test_rm_without_r_is_not_flagged(command):
    assert "rm_rf" not in scan_patterns(command, EXECUTABLE_PATTERNS)


# --- paths in a patch body (model-written file payloads) --------------------

PATCH_INPUTS = {
    "spaces then text, single line": "+++ a" + " " * N + "!",
    "trailing spaces, single line": "+++ a" + " " * N,
    "spaces and tabs": "+++ a" + " \t" * (N // 2) + "\r\n",
    "many lines": ("+++ a" + " " * 400 + "!\n") * 60,
    "V4A header": "*** Update File: a" + " " * N + "!",
}


@pytest.mark.parametrize("text", PATCH_INPUTS.values(), ids=PATCH_INPUTS.keys())
def test_patch_path_pattern_is_linear(text):
    _assert_fast(_PATCH_PATH.findall, text)
    _assert_fast(lambda t: _written_paths(AgentAction(kind="write_file", target="x", payload=t)), text)


@pytest.mark.parametrize(
    "body, path",
    [
        ("--- a/x\n+++ b/plugin/__init__.py\n@@", "plugin/__init__.py"),
        ("+++ b/plugin/__init__.py   \n", "plugin/__init__.py"),
        ("+++ b/plugin/__init__.py\r\n@@", "plugin/__init__.py"),
        ("*** Update File: my dir/guard.py\t\n", "my dir/guard.py"),
        ("*** Move to: x\n", "x"),
    ],
)
def test_patch_paths_are_still_read(body, path):
    assert path in _written_paths(AgentAction(kind="write_file", target="", payload=body))


# --- scope wording in the user's message (every user message, if opted in) --

SCOPE_INPUTS = {
    "comma then spaces": "," + " " * N,
    "newlines": "\n" * N,
    "CRLF": "\r\n" * (N // 2),
    "spaces across lines": ("," + " " * 400 + "\n") * 60,
    "many breaks": ", " * (N // 2),
    "quotes": ',"  ' * (N // 4),
    "words then spaces": "nichts" + " " * N,
}


@pytest.mark.parametrize("text", SCOPE_INPUTS.values(), ids=SCOPE_INPUTS.keys())
def test_scope_detection_is_linear(text):
    _assert_fast(detect_no_write_scope, text)
    _assert_fast(is_short_confirmation, text)


@pytest.mark.parametrize(
    "message",
    [
        "Bitte\n\n   nur lesen",
        "mach das.\n\"nur prüfen\"",
        "x, ( nur analysieren",
        "zeig es mir\r\nnichts ändern",
    ],
)
def test_scope_across_line_breaks_is_still_found(message):
    assert detect_no_write_scope(message) is True


# --- network fetches in a shell command (every terminal call) ---------------

from agent_security_guard.actions import _CLONE_COMMAND, _FETCH_CODE, _fetch_command  # noqa: E402

FETCH_INPUTS = {
    "many fetchers": "curl a " * (N // 7 + 1),
    "options with values": "curl -o " * (N // 8 + 1),
    "dotted word": "curl " + "a." * N + "1",
    "long host": "curl https://" + "a" * N + ".example/",
    "spaces": "curl" + " " * N + "x",
    "many lines": ("curl " + " " * 400 + "a\n") * 60,
    "clone spaces": "git" + " " * N + "x",
    "code dots": "requests" + "." * N,
}


@pytest.mark.parametrize("text", FETCH_INPUTS.values(), ids=FETCH_INPUTS.keys())
def test_fetch_detection_is_linear(text):
    _assert_fast(lambda t: (_fetch_command(t), _CLONE_COMMAND.search(t), _FETCH_CODE.search(t)), text)
