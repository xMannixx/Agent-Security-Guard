"""Tool names real agent hosts use, mapped to the tier of what they do.

The kind table in ``actions.py`` is the guard's own vocabulary (``shell``,
``http_post``, ...). Hosts forward their tools under their own names: Hermes
calls its shell ``terminal`` and its file writer ``write_file``, OpenClaw's are
``exec`` and ``write``. Left unrecognized, those fell through as "unknown
action", which is allowed, so "untrusted content cannot run a shell" held only
for a shell literally named ``shell``.

Names are matched exactly. Substrings are not safe: Hermes has
``read_terminal`` (a read), ``retrieval`` contains ``eval``, and ``todo_write``
is not a file write. A tool that is missing here is declared by the operator in
``tool_tiers`` (guard.yaml).

Every tier in this table is state-changing. Read tools are left out on purpose:
an unrecognized read is allowed either way, and stays audited.

stdlib-only.
"""

from __future__ import annotations

from typing import Dict

from .types import ActionTier

_EXECUTION = (
    # shells
    "bash", "sh", "zsh", "powershell", "pwsh", "terminal", "command",
    "run_terminal_cmd", "run_terminal_command", "run_in_terminal",
    "run_command", "run_shell", "run_shell_command", "shell_command",
    "shell_exec", "execute_command", "exec_command", "execute_shell",
    "execute_bash", "local_shell",
    # code runners
    "execute_code", "exec_code", "run_code", "code_execution",
    "code_interpreter", "python", "run_python", "execute_python",
    "python_repl", "run_script", "execute_script", "eval",
)

_LOCAL_WRITE = (
    "write_file", "write", "file_write", "write_to_file", "create_file",
    "save_file", "edit_file", "edit", "file_edit", "multi_edit", "multiedit",
    "notebook_edit", "notebookedit", "patch", "apply_patch", "patch_file",
    "apply_diff", "str_replace", "str_replace_editor",
    "str_replace_based_edit_tool", "search_replace", "replace_in_file",
    "insert_edit_into_file", "append_file", "append_to_file", "delete_file",
    "remove_file", "move_file", "rename_file", "copy_file", "create_directory",
)

# Messaging tools (``message``, ``send_message``) are deliberately absent: on
# Hermes and OpenClaw they are how the agent answers its own user.
_EXTERNAL_WRITE = (
    "send_email", "send_mail", "email_send", "upload", "upload_file", "git_push",
)

_SELF_MODIFICATION = (
    "skill_manage", "skill_update", "create_skill", "update_skill",
    "edit_skill", "patch_skill", "delete_skill",
)

# Memory tools (Hermes: ``memory``) are deliberately absent too. A raw tool call
# does not say which lane it writes, so as MEMORY_WRITE it would be judged as an
# evidence write and waved through even when untrusted content proposed it.
# Unrecognized, that same call is denied.

_INSTALL = (
    "install_package", "package_install", "apt_install", "brew_install",
    "install_skill", "install_plugin", "install_extension",
)

# Tools whose result is content from outside the machine: a web page, search
# results, a browser snapshot. Glob patterns over the tool name. What such a
# tool returns is data, whoever asked for it, and once it is in the model's
# context it may be what proposes the next action. The operator's list
# (``untrusted_content_tools`` in guard.yaml) replaces this one.
UNTRUSTED_CONTENT_TOOLS = (
    "web_fetch", "web_extract", "web_search", "webfetch", "websearch",
    "x_search", "http_get", "https_get", "fetch_url", "read_url", "scrape",
    "browser", "browser_*",
)

HOST_TOOL_TIER: Dict[str, ActionTier] = {
    **{name: ActionTier.EXECUTION for name in _EXECUTION},
    **{name: ActionTier.LOCAL_WRITE for name in _LOCAL_WRITE},
    **{name: ActionTier.EXTERNAL_WRITE for name in _EXTERNAL_WRITE},
    **{name: ActionTier.SELF_MODIFICATION for name in _SELF_MODIFICATION},
    **{name: ActionTier.INSTALL for name in _INSTALL},
}
