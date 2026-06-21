import pytest

from agent_security_guard import _miniyaml


def test_simple_mapping():
    data = _miniyaml.load("mode: autonomous-safe\ncount: 3\nflag: true\n")
    assert data == {"mode": "autonomous-safe", "count": 3, "flag": True}


def test_empty_inline_collections():
    data = _miniyaml.load("domain_allowlist: []\nextra: {}\n")
    assert data == {"domain_allowlist": [], "extra": {}}


def test_nested_mapping_and_sequence():
    text = (
        "tiers:\n"
        "  read_only: allow\n"
        "  external_write: require_confirmation\n"
        "sensitive_paths:\n"
        "  - .env\n"
        "  - \"*.pem\"\n"
        "  - .ssh/\n"
    )
    data = _miniyaml.load(text)
    assert data["tiers"]["read_only"] == "allow"
    assert data["tiers"]["external_write"] == "require_confirmation"
    assert data["sensitive_paths"] == [".env", "*.pem", ".ssh/"]


def test_double_quoted_regex_unescaping():
    # YAML double-quote: \\s -> \s, which is what the regex engine needs.
    data = _miniyaml.load('secret_patterns:\n  - "(?i)password\\\\s*[:=]"\n')
    assert data["secret_patterns"] == [r"(?i)password\s*[:=]"]


def test_single_quoted_preserves_backslashes():
    data = _miniyaml.load("p:\n  - '(?i)api[_-]?key'\n")
    assert data["p"] == ["(?i)api[_-]?key"]


def test_comments_are_stripped_outside_quotes():
    text = "# header\nmode: safe  # trailing comment\n"
    assert _miniyaml.load(text) == {"mode": "safe"}


def test_hash_inside_quotes_preserved():
    data = _miniyaml.load('token: "a#b"\n')
    assert data == {"token": "a#b"}


def test_tab_indentation_fails_loud():
    with pytest.raises(_miniyaml.MiniYAMLError):
        _miniyaml.load("tiers:\n\tread_only: allow\n")


def test_sequence_of_mappings_unsupported():
    with pytest.raises(_miniyaml.MiniYAMLError):
        _miniyaml.load("items:\n  - key: value\n")
