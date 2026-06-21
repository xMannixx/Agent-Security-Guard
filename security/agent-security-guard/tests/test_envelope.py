from agent_security_guard import OriginTrust, resolve_origin_trust


def test_source_kind_takes_priority_over_channel():
    # A web-fetch tool's payload is external_web, not trusted tool knowledge.
    trust = resolve_origin_trust(source="tool", channel="tool", source_kind="web_fetch")
    assert trust is OriginTrust.EXTERNAL_WEB


def test_calculator_is_trusted_tool_output():
    assert resolve_origin_trust(source_kind="calculator") is OriginTrust.TRUSTED_TOOL_OUTPUT


def test_local_grep_is_local_project():
    assert resolve_origin_trust(source_kind="grep") is OriginTrust.LOCAL_PROJECT


def test_email_is_external_document():
    assert resolve_origin_trust(source_kind="email") is OriginTrust.EXTERNAL_DOCUMENT


def test_generic_tool_output_is_untrusted():
    trust = resolve_origin_trust(source_kind="tool")
    assert trust is OriginTrust.TOOL_OUTPUT
    assert trust.is_untrusted is True


def test_user_is_trusted():
    assert resolve_origin_trust(source="user").is_trusted is True


def test_unknown_fails_safe():
    trust = resolve_origin_trust(source="???", channel="???")
    assert trust is OriginTrust.UNKNOWN
    assert trust.is_untrusted is True
