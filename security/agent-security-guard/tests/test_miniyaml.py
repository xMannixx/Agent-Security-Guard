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


# One-line lists and mappings. `[a, b]` used to come back as the text "[a, b]".


def test_flow_sequence_is_a_list():
    data = _miniyaml.load('sensitive_paths: [.env, "*.pem", \'a, b\', 8080, true]\n')
    assert data == {"sensitive_paths": [".env", "*.pem", "a, b", 8080, True]}


def test_flow_sequence_allows_a_trailing_comma_and_spaces():
    assert _miniyaml.load("a: [ x , y, ]\n") == {"a": ["x", "y"]}


def test_flow_mapping_is_a_mapping():
    data = _miniyaml.load("tool_tiers: {memory: unknown, deploy: execution}\n")
    assert data == {"tool_tiers": {"memory": "unknown", "deploy": "execution"}}


def test_flow_sequence_as_a_list_item():
    assert _miniyaml.load("a:\n  - [x, y]\n") == {"a": [["x", "y"]]}


@pytest.mark.parametrize("text", [
    "a: [x, [y]]",          # nested
    "a: {k: {x: 1}}",
    "a: [x, y",             # not closed on its line
    "a: {k: v",
    "a: [x, , y]",          # empty item
    "a: {k}",               # no value
    "a: [A-Z]{3}",          # text that starts like a list: quote it
])
def test_flow_collection_the_loader_cannot_read_fails_loud(text):
    with pytest.raises(_miniyaml.MiniYAMLError):
        _miniyaml.load(text)


# A key given twice. The later entry used to win.


@pytest.mark.parametrize("text", [
    "mode: strict\nmode: monitor\n",
    "tiers:\n  external_write: deny\n  external_write: allow\n",
    "tiers:\n  a: 1\nlimits:\n  b: 2\ntiers:\n  c: 3\n",
    "t: {a: 1, a: 2}\n",
    '"mode": strict\nmode: monitor\n',
])
def test_duplicate_key_fails_loud(text):
    with pytest.raises(_miniyaml.MiniYAMLError, match="twice"):
        _miniyaml.load(text)


def test_same_key_in_different_mappings_is_fine():
    data = _miniyaml.load("a:\n  path: x\nb:\n  path: y\n")
    assert data == {"a": {"path": "x"}, "b": {"path": "y"}}


def test_quoted_key_is_the_key():
    assert _miniyaml.load('"mode": strict\n\'a:b\': 1\n') == {"mode": "strict", "a:b": 1}


def test_colon_inside_a_plain_list_item_is_text():
    text = "hosts:\n  - example.com:8443\n  - C:/secrets/.env\n  - https://example.com/x\n"
    assert _miniyaml.load(text) == {
        "hosts": ["example.com:8443", "C:/secrets/.env", "https://example.com/x"]
    }


def test_document_start_marker_is_accepted_once():
    assert _miniyaml.load("---\nmode: strict\n") == {"mode": "strict"}
    with pytest.raises(_miniyaml.MiniYAMLError):
        _miniyaml.load("a: 1\n---\nb: 2\n")
