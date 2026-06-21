from agent_security_guard import ActionTier, AgentAction, classify_action


def test_get_is_read_only():
    assert classify_action(AgentAction(kind="http_get", target="https://x")) is ActionTier.READ_ONLY


def test_post_is_external_write():
    assert classify_action(AgentAction(kind="http_post", target="https://x")) is ActionTier.EXTERNAL_WRITE


def test_generic_http_uses_method():
    assert classify_action(AgentAction(kind="http", method="DELETE")) is ActionTier.EXTERNAL_WRITE
    assert classify_action(AgentAction(kind="http", method="GET")) is ActionTier.READ_ONLY
    assert classify_action(AgentAction(kind="http")) is ActionTier.READ_ONLY


def test_shell_is_execution():
    assert classify_action(AgentAction(kind="shell", target="ls")) is ActionTier.EXECUTION


def test_download_and_install():
    assert classify_action(AgentAction(kind="download", target="https://x/a.sh")) is ActionTier.DOWNLOAD
    assert classify_action(AgentAction(kind="pip_install", target="evilpkg")) is ActionTier.INSTALL


def test_local_read_vs_remote_read():
    assert classify_action(AgentAction(kind="read_file", target="/proj/.env")) is ActionTier.LOCAL_READ
    # Reading a remote URL is read-only, not a local read.
    assert classify_action(AgentAction(kind="read_file", target="https://x/page")) is ActionTier.READ_ONLY


def test_memory_and_config():
    assert classify_action(AgentAction(kind="memory_write")) is ActionTier.MEMORY_WRITE
    assert classify_action(AgentAction(kind="config_change")) is ActionTier.CONFIG_CHANGE


def test_unknown_kind_fails_safe_to_unknown():
    assert classify_action(AgentAction(kind="teleport")) is ActionTier.UNKNOWN


def test_unknown_kind_with_write_method():
    assert classify_action(AgentAction(kind="weird", method="PUT")) is ActionTier.EXTERNAL_WRITE
