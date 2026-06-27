"""Conservative text heuristics for user-scope signals (DE + EN).

These are an OFFER for a host/plugin to populate ``GuardContext`` flags from a
raw user message when it does not set them explicitly. The ``GuardContext``
flags remain the source of truth; these helpers only ever *suggest* turning a
gate ON (fail-safe direction). They are intentionally conservative: they match
clear, explicit phrases and avoid firing on ordinary prose.

stdlib-only.
"""

from __future__ import annotations

import re
from typing import List, Pattern

# Explicit "do not change anything" phrases. Matching any one puts the whole
# turn into a no-write scope. Kept phrase-level (not single words) to avoid
# false positives like "ändere nichts an deinem Stil" inside normal requests.
_NO_WRITE_PHRASES: List[str] = [
    # German
    r"nichts\s+ändern",
    r"keine\s+(?:datei|dateien)\s+ändern",
    r"keine\s+änderung(?:en)?",
    r"keinen\s+patch\s+(?:anwenden|machen)",
    r"nicht\s+patchen",
    r"nur\s+(?:einen\s+)?vorschlag",
    r"nur\s+vorschlagen",
    r"nur\s+analysieren",
    r"nur\s+prüfen",
    r"nur\s+lesen",
    r"keine\s+nebenaktion(?:en)?",
    r"nicht\s+ausführen",
    r"keine\s+ausführung",
    r"nichts\s+speichern",
    r"nicht\s+speichern",
    # English
    r"don'?t\s+(?:change|modify|write|patch|edit)\s+(?:any|anything|files?)?",
    r"do\s+not\s+(?:change|modify|write|patch|edit)\s+(?:any|anything|files?)?",
    r"no\s+(?:file\s+)?changes",
    r"no\s+writes?",
    r"don'?t\s+apply\s+(?:the\s+)?patch",
    r"(?:just|only)\s+(?:a\s+)?(?:suggest|proposal|propose|analyze|analyse|review|read)",
    r"suggestion\s+only",
    r"read[\s-]?only",
]

# Ambiguous short confirmations. The message must be ESSENTIALLY just this
# (optionally with light punctuation / a trailing "mach das"), otherwise a
# longer, concrete instruction is not a "short confirmation".
_SHORT_CONFIRMATION_PHRASES: List[str] = [
    # German
    r"ja",
    r"ok",
    r"oki",
    r"okay",
    r"klar",
    r"passt",
    r"weiter",
    r"genau",
    r"jup",
    r"jep",
    r"mach(?:'s|\s+das)?",
    r"mach\s+weiter",
    r"so\s+machen",
    r"klingt\s+gut",
    r"guter\s+punkt",
    r"ja[, ]+mach(?:'s|\s+das)?",
    r"ja\s+bitte",
    # English
    r"yes",
    r"yep",
    r"yeah",
    r"sure",
    r"go\s+ahead",
    r"do\s+it",
    r"sounds\s+good",
    r"go\s+for\s+it",
    r"proceed",
]


def _compile_alt(phrases: List[str]) -> Pattern:
    return re.compile("|".join(f"(?:{p})" for p in phrases), re.IGNORECASE)


_NO_WRITE_RE = _compile_alt(_NO_WRITE_PHRASES)
# Anchored: the entire (normalized) message must be one of the confirmations.
_SHORT_CONFIRMATION_RE = re.compile(
    r"^\W*(?:" + "|".join(f"(?:{p})" for p in _SHORT_CONFIRMATION_PHRASES) + r")\W*$",
    re.IGNORECASE,
)

# A short confirmation must also be short in length, as a second guard against
# matching a long sentence that merely starts with "ja, ...".
_MAX_SHORT_CONFIRMATION_CHARS = 24


def detect_no_write_scope(text: str) -> bool:
    """True if the user message clearly sets a no-write / suggestion-only scope."""
    if not text:
        return False
    return _NO_WRITE_RE.search(text) is not None


def is_short_confirmation(text: str) -> bool:
    """True if the message is essentially a bare, ambiguous confirmation.

    Conservative: the normalized message must consist solely of a known
    confirmation token and be short. "ja, mach das" matches; "ja, aber ändere
    zuerst X" does not.
    """
    if not text:
        return False
    normalized = text.strip()
    if len(normalized) > _MAX_SHORT_CONFIRMATION_CHARS:
        return False
    return _SHORT_CONFIRMATION_RE.match(normalized) is not None
