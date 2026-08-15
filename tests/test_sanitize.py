from __future__ import annotations

from yaysafe.sanitize import sanitize_terminal


def test_terminal_escape_and_osc_sequences_are_removed() -> None:
    hostile = "normal\x1b[31mred\x1b[0m\x1b]52;c;Y2xpcGJvYXJk\x07\x00end"
    cleaned = sanitize_terminal(hostile)
    assert "\x1b" not in cleaned
    assert "\x00" not in cleaned
    assert "Y2xpcGJvYXJk" not in cleaned
    assert cleaned.startswith("normalred")


def test_c1_and_bidirectional_terminal_controls_are_neutralized() -> None:
    cleaned = sanitize_terminal("safe\x9b31m\u202eevil\u2066name")
    assert "\x9b" not in cleaned
    assert "\u202e" not in cleaned
    assert "\u2066" not in cleaned
    assert cleaned == "safe?31m?evil?name"


def test_surrogates_and_zero_width_formatting_cannot_reach_the_terminal() -> None:
    cleaned = sanitize_terminal("safe\udcff\u200bname")
    assert cleaned == "safe??name"
