"""Compiled detector banks for the content scanner.

These are heuristics, not the guarantee. The guarantee comes from the
origin/action policy: even when nothing here matches, untrusted -> shell (and
friends) is still denied. Indicators raise the risk score and explain *why*
content looks dangerous; they never become the sole basis of a decision.

Three banks:
- INJECTION: prompt-injection and social-engineering directives
- EXECUTABLE: shell / code-execution payloads embedded in content
- (secret patterns are config-driven, see guard.yaml ``secret_patterns``)
"""

from __future__ import annotations

import re
from typing import List, Pattern, Tuple


# Prompt-injection + social-engineering directives. The point of detection is
# to flag content that *tries to act like an instruction*.
INJECTION_PATTERNS: List[Tuple[str, Pattern]] = [
    ("ignore_previous", re.compile(r"(?i)ignore\s+(all\s+)?(the\s+)?previous(\s+instructions?)?")),
    ("disregard_above", re.compile(r"(?i)disregard\s+(all\s+)?(the\s+)?(previous|above|prior|earlier)")),
    ("forget_instructions", re.compile(r"(?i)forget\s+(all\s+)?(your\s+)?(previous\s+)?instructions?")),
    ("fake_role_header", re.compile(r"(?im)^\s*(system|developer|assistant)\s*:")),
    ("you_are_now", re.compile(r"(?i)\byou\s+are\s+now\b")),
    ("new_instructions", re.compile(r"(?i)\bnew\s+instructions?\b")),
    ("override_rules", re.compile(r"(?i)\boverride\b[^.\n]{0,40}(instructions?|rules?|policy|policies)")),
    ("reveal_system_prompt", re.compile(r"(?i)(reveal|print|show|repeat)\s+(your\s+)?(the\s+)?(system|developer)\s+prompt")),
    ("operational_directive", re.compile(r"(?i)operational\s+directive")),
    ("required_by_owner", re.compile(r"(?i)required\s+by\s+the\s+(site|page|website)\s+owner")),
    ("do_not_tell_user", re.compile(r"(?i)do\s+not\s+(tell|inform|notify|mention\s+to)\s+the\s+user")),
    ("ask_user_to_confirm", re.compile(r"(?i)ask\s+the\s+user\s+to\s+(confirm|approve|allow)")),
    ("tell_user_to_run", re.compile(r"(?i)(tell|instruct|have)\s+the\s+user\s+to\s+(run|execute|install)")),
    ("send_env_vars", re.compile(r"(?i)send\s+(the\s+|your\s+|all\s+)?(diagnostic\s+)?(environment|env)\s+variables?")),
    ("include_in_next_call", re.compile(r"(?i)include\s+th(is|e\s+following)\b[^.\n]{0,60}(tool\s+call|request|response|prompt)")),
    ("for_accurate_include", re.compile(r"(?i)for\s+(accurate|correct|proper)\b[^.\n]{0,40}\binclude\b")),
    ("exfiltrate", re.compile(r"(?i)\bexfiltrat")),
    ("html_comment_directive", re.compile(r"(?is)<!--[^>]*?(instruction|system\s*:|ignore\s+previous|do\s+not\s+tell)[^>]*?-->")),
]

# Shell / code-execution payloads embedded in content.
EXECUTABLE_PATTERNS: List[Tuple[str, Pattern]] = [
    ("pipe_to_shell", re.compile(r"(?i)(curl|wget|fetch)\b[^\n|]{0,200}\|\s*(sudo\s+)?(ba|z|d|fi)?sh\b")),
    ("generic_pipe_shell", re.compile(r"(?i)\|\s*(sudo\s+)?(ba|z)?sh\b")),
    ("rm_rf", re.compile(r"(?i)\brm\s+-[a-z]*r[a-z]*f?\b")),
    ("sudo", re.compile(r"(?i)(^|\s)sudo\s+")),
    ("invoke_expression", re.compile(r"(?i)\b(iex|invoke-expression)\b")),
    ("powershell_encoded", re.compile(r"(?i)powershell[^\n]{0,80}-enc(odedcommand)?\b")),
    ("chmod_exec", re.compile(r"(?i)\bchmod\s+\+?x\b")),
    ("base64_decode_pipe", re.compile(r"(?i)base64\s+(-d|--decode)\b")),
    ("eval_exec_call", re.compile(r"(?i)\b(eval|exec)\s*\(")),
    ("netcat_reverse", re.compile(r"(?i)\bnc\b\s+-[a-z]*e\b")),
    ("os_system", re.compile(r"(?i)os\.system\s*\(")),
]


def scan_patterns(text: str, patterns: List[Tuple[str, Pattern]]) -> List[str]:
    """Return the names of all patterns that match ``text`` (stable order)."""
    if not text:
        return []
    return [name for name, pattern in patterns if pattern.search(text)]


def compile_patterns(raw: List[str]) -> List[Tuple[str, Pattern]]:
    """Compile config-supplied regex strings, skipping any that are invalid.

    A bad regex in config must not crash the guard; it is skipped (and the
    remaining detectors still run). Returns (label, compiled) tuples.
    """
    compiled: List[Tuple[str, Pattern]] = []
    for index, expr in enumerate(raw):
        try:
            compiled.append((f"secret_{index}", re.compile(expr)))
        except re.error:
            continue
    return compiled
