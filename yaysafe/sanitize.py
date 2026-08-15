from __future__ import annotations

import re
import unicodedata

_ANSI = re.compile(
    r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07]*(?:\x07|\x1b\\)|[PX^_].*?\x1b\\)", re.DOTALL
)
_DIRECTIONAL_CONTROLS = {
    *range(0x202A, 0x202F),
    *range(0x2066, 0x206A),
}


def sanitize_terminal(value: object, *, max_length: int = 4000) -> str:
    """Remove terminal controls from untrusted text while retaining readable whitespace."""
    text = _ANSI.sub("", str(value))
    result: list[str] = []
    for char in text:
        code = ord(char)
        if char in "\n\t" or (
            code >= 32
            and code != 127
            and not 0x80 <= code <= 0x9F
            and code not in _DIRECTIONAL_CONTROLS
            and unicodedata.category(char) not in {"Cc", "Cf", "Cs"}
        ):
            result.append(char)
        else:
            result.append("?")
        if len(result) >= max_length:
            result.append("…")
            break
    return "".join(result)


def safe_filename(value: str) -> str:
    return sanitize_terminal(value, max_length=512).replace("\n", "?").replace("\t", " ")
