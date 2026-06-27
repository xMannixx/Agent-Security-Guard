from agent_security_guard import detect_no_write_scope, is_short_confirmation


def test_no_write_scope_german():
    for text in (
        "Erstelle nur einen Vorschlag. Nichts ändern.",
        "Keine Datei ändern.",
        "Keinen Patch anwenden.",
        "Nur Vorschlag ausgeben.",
        "Bitte nur analysieren, nichts speichern.",
        "Nur prüfen, keine Änderungen.",
    ):
        assert detect_no_write_scope(text) is True, text


def test_no_write_scope_english():
    for text in (
        "Just a proposal, do not change anything.",
        "Don't modify any files.",
        "read-only please",
        "suggestion only",
        "No file changes.",
    ):
        assert detect_no_write_scope(text) is True, text


def test_no_write_scope_does_not_fire_on_normal_requests():
    for text in (
        "Patch communication-style/SKILL.md and add the rule.",
        "Please change foo to bar in test.txt.",
        "Summarize this document for me.",
        "",
    ):
        assert detect_no_write_scope(text) is False, text


def test_short_confirmation_positive():
    for text in (
        "ja",
        "ok",
        "okay",
        "ja, mach das",
        "mach das",
        "passt",
        "weiter",
        "yes",
        "go ahead",
        "do it",
    ):
        assert is_short_confirmation(text) is True, text


def test_short_confirmation_negative():
    for text in (
        "ja, aber ändere zuerst die Konfiguration in config.py",
        "Patch communication-style/SKILL.md and add a rule against X.",
        "yes, but first read the file and tell me what changes you plan",
        "okay so here is the full specification of what I want ...",
        "",
    ):
        assert is_short_confirmation(text) is False, text
