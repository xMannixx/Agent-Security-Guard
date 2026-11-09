"""A tiny, conservative YAML subset loader (stdlib-only).

agent-security-guard ships zero runtime dependencies, so we cannot rely on
PyYAML. This loader supports exactly the subset ``guard.yaml`` needs:

- block mappings (2-space indentation)
- block sequences of scalars (``- item``)
- one-line flow collections of scalars: ``[a, "b, c"]`` and ``{key: value}``
- scalars: int, float, ``true``/``false``, ``null``/``~``, and strings
  (single- or double-quoted, or plain)

Because it backs a *security* policy, it fails loudly (``ValueError``) on
anything it does not understand (tabs in indentation, sequences of mappings,
unterminated quotes, nested or multi-line flow collections, a key given
twice) instead of guessing. Never silently misparse a policy.

Two things it used to guess at: ``[a, b]`` came back as the text ``[a, b]``,
which a caller expecting a list then took apart into single characters, and of
two entries with the same key the later one won without a word.
"""

from __future__ import annotations

from typing import Any, List, Optional, Tuple


class MiniYAMLError(ValueError):
    """Raised on any construct outside the supported subset."""


def load(text: str) -> Any:
    """Parse a YAML-subset document into nested dict/list/scalars."""
    lines = _tokenize(text)
    if lines and lines[0][1] == "---":  # an explicit document start
        lines = lines[1:]
    if not lines:
        return {}
    value, consumed = _parse_block(lines, 0, lines[0][0])
    if consumed != len(lines):
        line_no = lines[consumed][2]
        raise MiniYAMLError(f"Unexpected indentation at line {line_no}")
    return value


# --------------------------------------------------------------------------- #
# Tokenizing
# --------------------------------------------------------------------------- #


def _tokenize(text: str) -> List[Tuple[int, str, int]]:
    """Return [(indent, content, line_number)] for meaningful lines."""
    tokens: List[Tuple[int, str, int]] = []
    for line_no, raw in enumerate(text.splitlines(), start=1):
        leading_ws = raw[: len(raw) - len(raw.lstrip())]
        if "\t" in leading_ws:
            raise MiniYAMLError(f"Tab in indentation at line {line_no}")
        content = _strip_comment(raw)
        if not content.strip():
            continue
        indent = len(content) - len(content.lstrip(" "))
        tokens.append((indent, content.strip(), line_no))
    return tokens


def _strip_comment(line: str) -> str:
    """Drop a trailing ``#`` comment that is outside quotes."""
    in_single = False
    in_double = False
    for i, ch in enumerate(line):
        if ch == "'" and not in_double:
            in_single = not in_single
        elif ch == '"' and not in_single:
            in_double = not in_double
        elif ch == "#" and not in_single and not in_double:
            if i == 0 or line[i - 1] in (" ", "\t"):
                return line[:i]
    return line


# --------------------------------------------------------------------------- #
# Block parsing
# --------------------------------------------------------------------------- #


def _parse_block(
    lines: List[Tuple[int, str, int]], start: int, indent: int
) -> Tuple[Any, int]:
    """Parse a block at the given indent; return (value, next_index)."""
    if lines[start][1].startswith("- "):
        return _parse_sequence(lines, start, indent)
    return _parse_mapping(lines, start, indent)


def _parse_mapping(
    lines: List[Tuple[int, str, int]], start: int, indent: int
) -> Tuple[Any, int]:
    result: dict = {}
    i = start
    while i < len(lines):
        line_indent, content, line_no = lines[i]
        if line_indent < indent:
            break
        if line_indent > indent:
            raise MiniYAMLError(f"Unexpected indentation at line {line_no}")
        if content.startswith("- "):
            raise MiniYAMLError(f"Unexpected sequence item at line {line_no}")
        key, rest = _split_entry(content, line_no)
        if key in result:
            # The later one used to win. Which of the two was meant is not
            # something to guess in a policy.
            raise MiniYAMLError(f"Key {key!r} is given twice (line {line_no})")
        if rest:
            result[key] = _parse_scalar(rest, line_no)
            i += 1
        else:
            # Nested block on following, more-indented lines.
            if i + 1 < len(lines) and lines[i + 1][0] > indent:
                value, i = _parse_block(lines, i + 1, lines[i + 1][0])
                result[key] = value
            else:
                result[key] = None
                i += 1
    return result, i


def _parse_sequence(
    lines: List[Tuple[int, str, int]], start: int, indent: int
) -> Tuple[Any, int]:
    result: list = []
    i = start
    while i < len(lines):
        line_indent, content, line_no = lines[i]
        if line_indent < indent:
            break
        if line_indent > indent:
            raise MiniYAMLError(f"Unexpected indentation at line {line_no}")
        if not content.startswith("- "):
            break
        item = content[2:].strip()
        if not item:
            raise MiniYAMLError(f"Empty sequence item at line {line_no}")
        if _is_mapping_item(item):
            raise MiniYAMLError(
                f"Sequences of mappings are unsupported at line {line_no}"
            )
        result.append(_parse_scalar(item, line_no))
        i += 1
    return result, i


# --------------------------------------------------------------------------- #
# Scalars
# --------------------------------------------------------------------------- #


def _outside_quotes(text: str):
    """Yield ``(index, character)`` for the characters not inside quotes."""
    quote = ""
    i = 0
    while i < len(text):
        ch = text[i]
        if quote:
            if ch == "\\" and quote == '"':
                i += 1  # the escaped character belongs to the string
            elif ch == quote:
                quote = ""
        elif ch in "\"'":
            quote = ch
        else:
            yield i, ch
        i += 1


def _is_mapping_item(item: str) -> bool:
    """Whether a sequence item is ``key: value``.

    A colon makes a mapping only when a space or the end of the line follows
    it: ``example.com:8443`` and ``C:/secrets`` are plain strings.
    """
    if item[0] in "[{":
        return False
    return any(
        ch == ":" and (i + 1 == len(item) or item[i + 1] == " ")
        for i, ch in _outside_quotes(item)
    )


def _split_entry(content: str, line_no: int) -> Tuple[str, str]:
    """Split ``key: value`` at the first colon that is not inside quotes."""
    for i, ch in _outside_quotes(content):
        if ch == ":":
            key = _parse_key(content[:i].strip(), line_no)
            return key, content[i + 1:].strip()
    raise MiniYAMLError(f"Expected 'key: value' at line {line_no}")


def _parse_key(token: str, line_no: int) -> str:
    if not token:
        raise MiniYAMLError(f"Missing key at line {line_no}")
    if token[0] in "\"'":
        return str(_parse_scalar(token, line_no))
    return token


def _parse_flow(token: str, line_no: int) -> Any:
    """A one-line flow collection of scalars: ``[a, "b, c"]`` or ``{k: v}``."""
    closer = "]" if token[0] == "[" else "}"
    if not token.endswith(closer):
        raise MiniYAMLError(
            f"Collection opened with {token[0]!r} is not closed on line {line_no} "
            "(quote the value if it is meant as text)"
        )
    body = token[1:-1]
    items: List[str] = []
    start = 0
    for i, ch in _outside_quotes(body):
        if ch in "[]{}":
            raise MiniYAMLError(f"Nested collections are unsupported at line {line_no}")
        if ch == ",":
            items.append(body[start:i].strip())
            start = i + 1
    items.append(body[start:].strip())
    if items[-1] == "":
        items.pop()  # empty collection, or a trailing comma
    if "" in items:
        raise MiniYAMLError(f"Empty item in a collection at line {line_no}")
    if closer == "]":
        return [_parse_scalar(item, line_no) for item in items]
    result: dict = {}
    for item in items:
        key, rest = _split_entry(item, line_no)
        if key in result:
            raise MiniYAMLError(f"Key {key!r} is given twice (line {line_no})")
        result[key] = _parse_scalar(rest, line_no) if rest else None
    return result


def _parse_scalar(token: str, line_no: int) -> Any:
    if token[0] in "[{":
        return _parse_flow(token, line_no)
    if token.startswith('"'):
        return _parse_double_quoted(token, line_no)
    if token.startswith("'"):
        return _parse_single_quoted(token, line_no)
    lowered = token.lower()
    if lowered in ("true", "false"):
        return lowered == "true"
    if lowered in ("null", "~"):
        return None
    parsed_int = _try_int(token)
    if parsed_int is not None:
        return parsed_int
    parsed_float = _try_float(token)
    if parsed_float is not None:
        return parsed_float
    return token


def _parse_double_quoted(token: str, line_no: int) -> str:
    if len(token) < 2 or not token.endswith('"'):
        raise MiniYAMLError(f"Unterminated double-quoted string at line {line_no}")
    body = token[1:-1]
    out: List[str] = []
    escapes = {"\\": "\\", '"': '"', "n": "\n", "t": "\t", "r": "\r", "0": "\0"}
    i = 0
    while i < len(body):
        ch = body[i]
        if ch == "\\":
            if i + 1 >= len(body):
                raise MiniYAMLError(f"Dangling escape at line {line_no}")
            nxt = body[i + 1]
            out.append(escapes.get(nxt, "\\" + nxt))
            i += 2
        else:
            out.append(ch)
            i += 1
    return "".join(out)


def _parse_single_quoted(token: str, line_no: int) -> str:
    if len(token) < 2 or not token.endswith("'"):
        raise MiniYAMLError(f"Unterminated single-quoted string at line {line_no}")
    return token[1:-1].replace("''", "'")


def _try_int(token: str) -> Optional[int]:
    try:
        if token.lstrip("-+").isdigit():
            return int(token)
    except ValueError:
        return None
    return None


def _try_float(token: str) -> Optional[float]:
    try:
        return float(token)
    except ValueError:
        return None
