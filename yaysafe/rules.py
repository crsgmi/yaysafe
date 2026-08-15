from __future__ import annotations

import re
import shlex
from dataclasses import dataclass

from yaysafe.models import Finding, InspectedFile, PackageMetadata, Risk


@dataclass(frozen=True, slots=True)
class Rule:
    rule_id: str
    severity: Risk
    pattern: re.Pattern[str]
    description: str
    category: str
    install_boost: bool = False
    hard: bool = False


def _rx(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern, re.IGNORECASE)


RULES: tuple[Rule, ...] = (
    Rule(
        "remote-pipe-shell",
        Risk.HIGH,
        _rx(
            r"\b(?:curl|wget)\b[^;&\n]{0,700}\|\s*(?:sudo\s+|env\s+)?"
            r"(?:[^\s;|]*/)?(?:ba|z|fi)?sh\b"
        ),
        "Downloads and executes a remote shell script directly.",
        "remote-code-execution",
        hard=True,
    ),
    Rule(
        "dynamic-shell",
        Risk.HIGH,
        _rx(r"\b(?:ba|z|fi)?sh\s+-c\s+['\"$]|\b(?:python\d*\s+-c|perl\s+-e)\b"),
        "Executes dynamically supplied code.",
        "dynamic-execution",
    ),
    Rule(
        "eval",
        Risk.MEDIUM,
        _rx(r"(^|[;&|]\s*)eval\s+"),
        "Uses eval for dynamic shell execution.",
        "dynamic-execution",
    ),
    Rule(
        "suspicious-exec",
        Risk.HIGH,
        _rx(r"(^|[;&|]\s*)exec\s+[^\n]*(?:/tmp/|/var/tmp/|\$\(|`|base64|curl|wget)"),
        "Executes a temporary or dynamically constructed command target.",
        "dynamic-execution",
    ),
    Rule(
        "base64-exec",
        Risk.HIGH,
        _rx(r"base64\s+(?:--decode|-d)[^|;\n]*(?:\||;|&&)[^\n]*(?:sh|eval|exec|python|perl)"),
        "Decodes data and immediately executes it.",
        "obfuscation",
        hard=True,
    ),
    Rule(
        "reverse-shell",
        Risk.CRITICAL,
        _rx(
            r"/dev/tcp/|\b(?:nc|netcat|ncat)\b[^\n]*(?:-e\b|/bin/(?:ba)?sh)|\bsocat\b[^\n]*(?:exec|pty)"
        ),
        "Contains a probable reverse-shell or interactive network shell pattern.",
        "remote-access",
        hard=True,
    ),
    Rule(
        "ssh-network",
        Risk.MEDIUM,
        _rx(r"(^|[;&|]\s*)(?:ssh|scp|sftp)\s+"),
        "Initiates an SSH-family network connection during packaging.",
        "unexpected-network",
    ),
    Rule(
        "embedded-private-key",
        Risk.CRITICAL,
        _rx(r"BEGIN (?:OPENSSH|RSA|EC) PRIVATE KEY"),
        "Contains embedded private-key material.",
        "credential-access",
        True,
    ),
    Rule(
        "cron",
        Risk.HIGH,
        _rx(r"\b(?:crontab|/etc/cron(?:\.|/)|/var/spool/cron)"),
        "Creates or changes cron persistence.",
        "persistence",
        True,
    ),
    Rule(
        "systemd-enable",
        Risk.HIGH,
        _rx(r"\bsystemctl\b[^\n]*(?:enable|preset|start|daemon-reload)\b"),
        "Activates or persists a systemd unit on the host.",
        "persistence",
        True,
    ),
    Rule(
        "privilege",
        Risk.HIGH,
        _rx(r"(^|[;&|]\s*)(?:sudo|su)\b"),
        "Attempts privilege escalation from package build content.",
        "privilege-escalation",
        True,
    ),
    Rule(
        "world-writable",
        Risk.MEDIUM,
        _rx(r"\bchmod\b[^\n]*(?:777|a\+rwx)\b"),
        "Creates world-writable permissions.",
        "permissions",
    ),
    Rule(
        "setuid",
        Risk.HIGH,
        _rx(r"\b(?:chmod\b[^\n]*(?:[24][0-7]{3}|[ug]\+s)|setcap\b)"),
        "Grants set-ID bits or Linux capabilities.",
        "privilege-escalation",
    ),
    Rule(
        "disk-destructive",
        Risk.CRITICAL,
        _rx(r"(^|[;&|]\s*)(?:mkfs(?:\.[a-z0-9]+)?|fdisk|parted)\b|\bdd\b[^\n]*\bof=/dev/"),
        "Can overwrite or repartition block devices.",
        "destructive-action",
        True,
        True,
    ),
    Rule(
        "mount",
        Risk.MEDIUM,
        _rx(r"(^|[;&|]\s*)(?:mount|umount)\s+"),
        "Changes host mount state.",
        "host-modification",
        True,
    ),
    Rule(
        "firewall",
        Risk.HIGH,
        _rx(r"(^|[;&|]\s*)(?:iptables|nft)\s+"),
        "Changes host firewall rules.",
        "host-modification",
        True,
    ),
    Rule(
        "credential-environment",
        Risk.HIGH,
        _rx(r"\$(?:\{)?(?:AWS_SECRET_ACCESS_KEY|GITHUB_TOKEN|NPM_TOKEN)(?:\})?"),
        "Reads a credential-bearing environment variable.",
        "credential-access",
        True,
    ),
    Rule(
        "gpg-secret-export",
        Risk.HIGH,
        _rx(r"(?:^|[;&|]\s*)gpg\b[^\n]*--export-secret"),
        "Exports GPG private keys.",
        "credential-access",
        True,
    ),
    Rule(
        "large-encoded",
        Risk.MEDIUM,
        re.compile(r"[A-Za-z0-9+/]{300,}={0,2}"),
        "Contains a large encoded-looking payload.",
        "obfuscation",
    ),
    Rule(
        "network-exfil",
        Risk.CRITICAL,
        _rx(
            r"(?:curl|wget|nc|socat)\b[^\n]*(?:--data|-d\s|--upload-file|-T\s)[^\n]*(?:token|secret|passwd|shadow|\.ssh|\.aws|\.gnupg|wallet)"
        ),
        "Appears to transmit sensitive local data.",
        "data-exfiltration",
        True,
        True,
    ),
    Rule(
        "credential-pipe-exfil",
        Risk.CRITICAL,
        _rx(
            r"(?:\.ssh/id_[a-z0-9_-]+|\.aws/credentials|\.gnupg/private-keys|"
            r"wallet\.dat|(?:token|secret|credential)[^|\n]*)[^|\n]*\|\s*"
            r"(?:curl|wget|nc|socat)\b[^\n]*(?:--data|-d\s|--upload-file|-T\s)"
        ),
        "Pipes credential-sensitive local data into a network upload command.",
        "data-exfiltration",
        True,
        True,
    ),
    Rule(
        "network-download",
        Risk.LOW,
        _rx(r"(?:^|[;&|]\s*)(?:curl|wget)\b"),
        "Downloads data during a package function; verify that it is expected upstream content.",
        "unexpected-network",
    ),
)


_DOWNLOAD_TO_FILE = re.compile(
    r"\b(?:curl\b[^\n]*(?:-o|--output)\s+|wget\b[^\n]*(?:-O|--output-document(?:=|\s)+))(['\"]?[^\s;&|]+['\"]?)|\bcurl\b[^\n>]*>\s*(['\"]?[^\s;&|]+['\"]?)",
    re.IGNORECASE,
)

_SENSITIVE_PATH = re.compile(
    r"(?:"
    r"(?:(?:~|\$HOME|\$\{HOME\}|/home/[^/\s;&|<>]+)/)"
    r"(?:\.config|\.ssh|\.gnupg|\.aws|\.mozilla|\.local/share/(?:keyrings|kwalletd)|"
    r"\.bitcoin|\.electrum|\.bashrc|\.zshrc|\.profile|\.bash_profile|\.netrc)"
    r"|(?:~|\$HOME|\$\{HOME\}|/home/[^/\s;&|<>]+)(?=$|[\s;&|<>])"
    r"|/(?:etc|usr|bin|sbin|boot|opt|var|root|home)(?=/|\b)"
    r")[^\s;&|<>]*",
    re.IGNORECASE,
)

_COMMAND_SEPARATORS = {";", ";;", "&&", "||", "|", "&"}
_OUTPUT_COMMANDS = {"echo", "printf"}
_PASSIVE_TEXT_COMMANDS = _OUTPUT_COMMANDS | {
    "awk",
    "cat",
    "cut",
    "grep",
    "head",
    "less",
    "more",
    "sed",
    "tail",
    "tee",
    "tr",
}
_READ_COMMANDS = {
    ".",
    "awk",
    "base64",
    "bash",
    "cat",
    "cmp",
    "cut",
    "diff",
    "fish",
    "grep",
    "head",
    "less",
    "more",
    "perl",
    "python",
    "python2",
    "python3",
    "readlink",
    "sh",
    "source",
    "stat",
    "tail",
    "test",
    "wc",
    "xxd",
    "zsh",
}
_COPY_COMMANDS = {"cp", "install", "ln"}
_WRITE_COMMANDS = {"chmod", "chown", "chgrp", "mkdir", "mkfifo", "touch"}
_DESTRUCTIVE_COMMANDS = {"rm", "rmdir", "shred", "truncate", "unlink"}
_SHELL_SYNTAX_RULES = {
    "base64-exec",
    "credential-pipe-exfil",
    "dynamic-shell",
    "eval",
    "remote-pipe-shell",
    "suspicious-exec",
}


@dataclass(frozen=True, slots=True)
class _PathUse:
    path: str
    operation: str


@dataclass(frozen=True, slots=True)
class _ShellLine:
    number: int
    text: str


def _shell_tokens(line: str) -> list[str]:
    try:
        lexer = shlex.shlex(line, posix=True, punctuation_chars=";&|<>(){}")
        lexer.whitespace_split = True
        lexer.commenters = "#"
        return list(lexer)
    except ValueError:
        return []


def _shell_segments(line: str) -> list[list[str]]:
    tokens = _shell_tokens(line)
    segments: list[list[str]] = []
    current: list[str] = []
    for token in tokens:
        if token in _COMMAND_SEPARATORS:
            if current:
                segments.append(current)
                current = []
        else:
            current.append(token)
    if current:
        segments.append(current)
    return segments


def _strip_shell_comment(line: str) -> str:
    """Remove an unquoted shell comment without interpreting the command."""
    quote = ""
    escaped = False
    for index, char in enumerate(line):
        if escaped:
            escaped = False
            continue
        if char == "\\" and quote != "'":
            escaped = True
            continue
        if char in {"'", '"'}:
            if not quote:
                quote = char
            elif quote == char:
                quote = ""
            continue
        if char == "#" and not quote and (index == 0 or line[index - 1].isspace()):
            return line[:index]
    return line


def _command_substitutions(line: str) -> list[str]:
    """Extract active command/process substitutions without executing or expanding them."""
    substitutions: list[str] = []
    quote = ""
    escaped = False
    index = 0
    while index < len(line):
        char = line[index]
        if escaped:
            escaped = False
            index += 1
            continue
        if char == "\\" and quote != "'":
            escaped = True
            index += 1
            continue
        if char == "'":
            quote = "" if quote == "'" else "'" if not quote else quote
            index += 1
            continue
        if char == '"':
            quote = "" if quote == '"' else '"' if not quote else quote
            index += 1
            continue
        if char == "`" and quote != "'":
            end = index + 1
            while end < len(line):
                if line[end] == "`" and line[end - 1] != "\\":
                    substitutions.append(line[index + 1 : end])
                    index = end + 1
                    break
                end += 1
            else:
                index += 1
            continue
        starts_substitution = (
            char == "$" and index + 1 < len(line) and line[index + 1] == "("
        ) or (char in {"<", ">"} and index + 1 < len(line) and line[index + 1] == "(")
        if starts_substitution and quote != "'":
            depth = 1
            start = index + 2
            end = start
            inner_quote = ""
            inner_escaped = False
            while end < len(line) and depth:
                current = line[end]
                if inner_escaped:
                    inner_escaped = False
                elif current == "\\" and inner_quote != "'":
                    inner_escaped = True
                elif current in {"'", '"'}:
                    if not inner_quote:
                        inner_quote = current
                    elif inner_quote == current:
                        inner_quote = ""
                elif not inner_quote:
                    if current == "(":
                        depth += 1
                    elif current == ")":
                        depth -= 1
                end += 1
            if depth == 0:
                body = line[start : end - 1]
                substitutions.append(body)
                substitutions.extend(_command_substitutions(body))
                index = end
                continue
        index += 1
    return substitutions


_QUOTED_ASSIGNMENT = re.compile(
    r"(?P<prefix>(?:^|[;&]\s*)(?:export\s+|local\s+|readonly\s+)?"
    r"[A-Za-z_][A-Za-z0-9_]*\s*=\s*)"
    r"(?:'(?:[^']*)'|\"(?:\\.|[^\"])*\")"
)


def _mask_quoted_assignment_data(line: str) -> str:
    """Hide inert assignment literals from execution-pattern rules."""
    return _QUOTED_ASSIGNMENT.sub(lambda match: match.group("prefix") + "''", line)


def _has_line_continuation(line: str) -> bool:
    """Return whether a physical shell line ends in an active backslash continuation."""
    code = _strip_shell_comment(line).rstrip()
    if not code:
        return False
    trailing = len(code) - len(code.rstrip("\\"))
    if trailing % 2 == 0:
        return False
    # Backslash-newline is inactive inside single quotes.
    quote = ""
    escaped = False
    for char in code[:-1]:
        if escaped:
            escaped = False
        elif char == "\\" and quote != "'":
            escaped = True
        elif char in {"'", '"'}:
            if not quote:
                quote = char
            elif quote == char:
                quote = ""
    return quote != "'"


def _heredoc_marker(line: str) -> tuple[str, bool] | None:
    """Return an unquoted here-document delimiter and whether tabs are stripped."""
    tokens = _shell_tokens(line)
    for index, token in enumerate(tokens):
        if token != "<<":
            continue
        marker_index = index + 1
        strip_tabs = False
        if marker_index < len(tokens) and tokens[marker_index].startswith("-"):
            strip_tabs = True
            if tokens[marker_index] == "-":
                marker_index += 1
            else:
                marker = tokens[marker_index][1:]
                if marker and re.fullmatch(r"[^\s;&|<>(){}]+", marker):
                    return marker, strip_tabs
        if marker_index < len(tokens):
            marker = tokens[marker_index]
            if marker and re.fullmatch(r"[^\s;&|<>(){}]+", marker):
                return marker, strip_tabs
    return None


def _heredoc_is_executable(line: str) -> bool:
    commands = [
        command
        for segment in _shell_segments(line)
        if (command_at := _command_index(segment)) is not None
        for command in [segment[command_at].rsplit("/", 1)[-1].lower()]
    ]
    interpreters = {
        "bash",
        "dash",
        "fish",
        "ksh",
        "perl",
        "python",
        "python2",
        "python3",
        "sh",
        "zsh",
    }
    return any(command in interpreters for command in commands)


def _logical_shell_lines(content: str) -> list[_ShellLine]:
    """Create analyzable logical lines while keeping inert heredoc bodies as data.

    This is deliberately a lexer-level heuristic, not a shell interpreter. It joins
    backslash continuations and recognizes here-documents so printed documentation is
    not mistaken for executable code. Bodies fed directly to an interpreter remain
    analyzable.
    """
    physical = content.splitlines()
    result: list[_ShellLine] = []
    heredoc: tuple[str, bool, bool] | None = None
    index = 0
    while index < len(physical):
        number = index + 1
        line = physical[index]
        index += 1
        if heredoc is not None:
            active_marker, strip_tabs, executable = heredoc
            candidate = line.lstrip("\t") if strip_tabs else line
            if candidate == active_marker:
                heredoc = None
            elif executable:
                result.append(_ShellLine(number, line))
            continue

        parts = [line]
        while _has_line_continuation(parts[-1]) and index < len(physical):
            parts[-1] = parts[-1].rstrip()[:-1]
            parts.append(physical[index])
            index += 1
        logical = " ".join(part.strip() for part in parts)
        result.append(_ShellLine(number, logical))
        heredoc_marker = _heredoc_marker(logical)
        if heredoc_marker is not None:
            heredoc = (*heredoc_marker, _heredoc_is_executable(logical))
    return result


def _command_index(tokens: list[str]) -> int | None:
    start = len(tokens) - 1 - tokens[::-1].index("{") + 1 if "{" in tokens else 0
    while start < len(tokens) and tokens[start] in {"{", "}", "(", ")", "then", "do", "if"}:
        start += 1
    while start < len(tokens) and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", tokens[start]):
        start += 1
    while start < len(tokens) and tokens[start] in {"command", "builtin", "env", "sudo"}:
        wrapper = tokens[start]
        start += 1
        value_options = (
            {"-u", "--unset"}
            if wrapper == "env"
            else {
                "-C",
                "--close-from",
                "-D",
                "--chdir",
                "-g",
                "--group",
                "-h",
                "--host",
                "-p",
                "--prompt",
                "-R",
                "--chroot",
                "-T",
                "--command-timeout",
                "-u",
                "--user",
            }
            if wrapper == "sudo"
            else set()
        )
        while start < len(tokens) and tokens[start].startswith("-"):
            option = tokens[start].split("=", 1)[0]
            start += 1
            if option in value_options and "=" not in tokens[start - 1] and start < len(tokens):
                start += 1
        if wrapper == "env":
            while start < len(tokens) and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", tokens[start]):
                start += 1
    return start if start < len(tokens) else None


def _extract_paths(token: str) -> list[str]:
    if re.match(r"^(?:(?:git|svn|hg|bzr)\+)?https?://", token, re.IGNORECASE):
        return []
    paths = [match.group(0).rstrip("'\"),.:]") for match in _SENSITIVE_PATH.finditer(token)]
    if paths and re.search(r"\$(?:\{)?(?:pkgdir|srcdir)(?:\})?", token, re.IGNORECASE):
        return [token]
    return paths


def _redirection_operation(token: str) -> str | None:
    if "<<" in token:
        return None
    if ">" in token:
        return "write"
    if "<" in token:
        return "read"
    return None


def _path_uses(tokens: list[str]) -> tuple[str, list[_PathUse]]:
    command_at = _command_index(tokens)
    if command_at is None:
        return "", []
    command = tokens[command_at].rsplit("/", 1)[-1].lower()
    uses: list[_PathUse] = []
    consumed: set[int] = set()

    for index in range(command_at + 1, len(tokens) - 1):
        operation = _redirection_operation(tokens[index])
        if operation:
            consumed.update({index, index + 1})
            uses.extend(_PathUse(path, operation) for path in _extract_paths(tokens[index + 1]))

    operands = [
        (index, token)
        for index, token in enumerate(tokens[command_at + 1 :], command_at + 1)
        if index not in consumed and token not in {"{", "}", "(", ")"}
    ]
    path_operands = [
        (index, path)
        for index, token in operands
        if not token.startswith("-")
        for path in _extract_paths(token)
    ]

    if command in _OUTPUT_COMMANDS:
        return command, uses
    if command in {"grep", "awk"}:
        non_options = [(index, token) for index, token in operands if not token.startswith("-")]
        file_indexes = {index for index, _ in non_options[1:]}
        uses.extend(
            _PathUse(path, "read") for index, path in path_operands if index in file_indexes
        )
        if command == "grep":
            for option_index, token in operands:
                if token in {"-f", "--file"} and option_index + 1 < len(tokens):
                    uses.extend(
                        _PathUse(path, "read") for path in _extract_paths(tokens[option_index + 1])
                    )
    elif command in _READ_COMMANDS:
        uses.extend(_PathUse(path, "read") for _, path in path_operands)
    elif command in _COPY_COMMANDS and operands:
        non_options = [(index, token) for index, token in operands if not token.startswith("-")]
        destination_index = non_options[-1][0] if non_options else -1
        uses.extend(
            _PathUse(path, "write" if index == destination_index else "read")
            for index, path in path_operands
        )
    elif command == "mv" and operands:
        non_options = [(index, token) for index, token in operands if not token.startswith("-")]
        destination_index = non_options[-1][0] if non_options else -1
        uses.extend(
            _PathUse(path, "write" if index == destination_index else "destructive")
            for index, path in path_operands
        )
    elif command in _WRITE_COMMANDS:
        uses.extend(_PathUse(path, "write") for _, path in path_operands)
    elif command in _DESTRUCTIVE_COMMANDS:
        uses.extend(_PathUse(path, "destructive") for _, path in path_operands)
        uses.extend(
            _PathUse(token, "destructive")
            for _, token in operands
            if token == "/" or token.startswith("/*")
        )
    elif command == "sed":
        operation = (
            "write"
            if any(token == "-i" or token.startswith("-i") for _, token in operands)
            else "read"
        )
        non_options = [(index, token) for index, token in operands if not token.startswith("-")]
        file_indexes = {index for index, _ in non_options[1:]}
        uses.extend(
            _PathUse(path, operation) for index, path in path_operands if index in file_indexes
        )
    elif command == "find":
        operation = "destructive" if any(token == "-delete" for _, token in operands) else "read"
        expression_start = next(
            (
                index
                for index, token in operands
                if token.startswith("-") or token in {"!", "(", ")"}
            ),
            len(tokens),
        )
        uses.extend(
            _PathUse(path, operation) for index, path in path_operands if index < expression_start
        )
    elif command == "tee":
        uses.extend(_PathUse(path, "write") for _, path in path_operands)
    elif command in {"scp", "rsync"}:
        non_options = [(index, token) for index, token in operands if not token.startswith("-")]
        destination = non_options[-1][1] if non_options else ""
        destination_index = non_options[-1][0] if non_options else -1
        remote_destination = bool(re.match(r"(?:[^/\s]+@)?[^:\s]+:", destination))
        uses.extend(
            _PathUse(
                path,
                "write"
                if index == destination_index
                else "exfiltration"
                if remote_destination
                else "read",
            )
            for index, path in path_operands
        )
    elif command in {"curl", "wget", "sftp"}:
        upload = any(
            token.lower()
            in {
                "-d",
                "-f",
                "-t",
                "--data",
                "--data-ascii",
                "--data-binary",
                "--data-raw",
                "--data-urlencode",
                "--form",
                "--form-string",
                "--upload-file",
                "--post-file",
            }
            or token.lower().startswith(
                (
                    "--data=",
                    "--data-ascii=",
                    "--data-binary=",
                    "--data-raw=",
                    "--data-urlencode=",
                    "--form=",
                    "--form-string=",
                    "--upload-file=",
                    "--post-file=",
                )
            )
            for _, token in operands
        )
        operation = "exfiltration" if upload else "read"
        uses.extend(_PathUse(path, operation) for _, path in path_operands)
    elif command == "dd":
        for _, token in operands:
            operation = (
                "read" if token.startswith("if=") else "write" if token.startswith("of=") else ""
            )
            if operation:
                uses.extend(_PathUse(path, operation) for path in _extract_paths(token))
    return command, uses


def _is_staged_path(path: str) -> bool:
    normalized = path.lower().replace("${pkgdir}", "$pkgdir").replace("${srcdir}", "$srcdir")
    return "$pkgdir" in normalized or "$srcdir" in normalized


def _app_config_path(path: str, package_name: str) -> bool:
    normalized = path.lower().replace("${home}", "$home")
    match = re.search(r"/\.config/([^/]+)", normalized)
    if not match:
        return False
    package = re.sub(r"-(?:git|hg|svn|bzr|bin)$", "", package_name.lower())
    return match.group(1) in {package, package.replace("-", "")}


def _path_finding(
    use: _PathUse,
    file: str,
    line: int,
    evidence: str,
    metadata: PackageMetadata,
    *,
    is_install: bool,
) -> Finding | None:
    path = use.path
    if _is_staged_path(path):
        return None
    lowered = path.lower().replace("${home}", "$home")
    operation = use.operation
    hard = False

    if operation == "destructive" and (lowered == "/" or lowered.startswith("/*")):
        severity = Risk.CRITICAL
        rule_id = "dangerous-rm"
        description = "Destructively targets the host filesystem root."
        category = "destructive-action"
        hard = True
    elif operation == "destructive" and (
        lowered in {"~", "$home"} or re.fullmatch(r"/home/[^/]+", lowered)
    ):
        severity = Risk.CRITICAL
        rule_id = "home-directory-destructive"
        description = "Destructively targets an entire user home directory."
        category = "destructive-action"
        hard = True
    elif operation == "exfiltration":
        severity = Risk.CRITICAL
        rule_id = "network-exfil"
        description = "Transmits sensitive local data over the network."
        category = "data-exfiltration"
        hard = True
    elif "authorized_keys" in lowered:
        severity = Risk.CRITICAL if operation in {"write", "destructive"} else Risk.HIGH
        rule_id = f"authorized-keys-{operation}"
        description = f"{operation.title()}s an SSH authorized_keys persistence file."
        category = "persistence" if operation != "read" else "credential-access"
        hard = operation in {"write", "destructive"}
    elif re.search(r"/(?:\.ssh|root/\.ssh)/id_[^/]+", lowered) or any(
        marker in lowered
        for marker in (
            "/.gnupg/private-keys-v1.d",
            "/.gnupg/secring.gpg",
            "/.aws/credentials",
            "/.netrc",
            "/etc/shadow",
            "/etc/gshadow",
            "login data",
            "cookies.sqlite",
            "/.local/share/keyrings",
        )
    ):
        severity = Risk.CRITICAL if operation == "destructive" else Risk.HIGH
        rule_id = f"credential-sensitive-{operation}"
        description = f"{operation.title()}s credential-sensitive local data."
        category = "credential-access" if operation == "read" else "host-modification"
        hard = operation == "destructive"
    elif any(
        marker in lowered
        for marker in (
            "/.mozilla/firefox",
            "/google-chrome",
            "/chromium/default",
            "/chromium/profile",
        )
    ):
        severity = Risk.CRITICAL if operation == "destructive" else Risk.HIGH
        rule_id = f"browser-profile-{operation}"
        description = f"{operation.title()}s a browser profile or credential store."
        category = "credential-access"
    elif any(
        marker in lowered for marker in ("/.bitcoin", "/.electrum", "wallet.dat", "/metamask")
    ):
        severity = Risk.CRITICAL if operation != "read" else Risk.HIGH
        rule_id = f"wallet-{operation}"
        description = f"{operation.title()}s cryptocurrency wallet material."
        category = "credential-access"
    elif re.search(r"/\.(?:bashrc|zshrc|profile|bash_profile)(?:/|$)", lowered):
        severity = Risk.HIGH if operation in {"write", "destructive"} else Risk.LOW
        rule_id = f"shell-profile-{operation}"
        description = f"{operation.title()}s a user shell startup file."
        category = "persistence" if operation != "read" else "host-access"
    elif "/.ssh/" in lowered or lowered.endswith("/.ssh"):
        severity = Risk.HIGH if operation in {"write", "destructive"} else Risk.LOW
        rule_id = f"ssh-config-{operation}"
        description = f"{operation.title()}s SSH configuration data."
        category = "host-modification" if operation != "read" else "host-access"
    elif "/.gnupg/" in lowered or lowered.endswith("/.gnupg"):
        severity = Risk.HIGH if operation in {"write", "destructive"} else Risk.LOW
        rule_id = f"gpg-config-{operation}"
        description = f"{operation.title()}s GPG configuration data."
        category = "host-modification" if operation != "read" else "host-access"
    elif "/.config" in lowered:
        if operation == "read":
            severity = Risk.LOW if _app_config_path(path, metadata.name) else Risk.MEDIUM
        elif operation == "write":
            severity = Risk.MEDIUM if _app_config_path(path, metadata.name) else Risk.HIGH
        else:
            severity = Risk.HIGH
        rule_id = f"user-config-{operation}"
        description = f"{operation.title()}s the current user's configuration data."
        category = "host-modification" if operation != "read" else "host-access"
    elif re.match(r"/(?:etc|usr|bin|sbin|boot|opt|var|root|home)(?:/|$)", lowered):
        if operation == "read":
            severity = Risk.LOW
            rule_id = "direct-host-read"
        elif operation == "write":
            severity = Risk.CRITICAL if is_install else Risk.HIGH
            rule_id = "direct-host-write"
        else:
            severity = Risk.CRITICAL if is_install else Risk.HIGH
            rule_id = "dangerous-rm"
        description = (
            f"{operation.title()}s a sensitive host path outside the $pkgdir staging root."
        )
        category = "host-modification" if operation != "read" else "host-access"
        hard = operation == "destructive" or (
            operation == "write" and lowered.startswith(("/boot/", "/etc/sudoers"))
        )
    else:
        return None

    return Finding(
        severity,
        rule_id,
        file,
        line,
        evidence[:500],
        description,
        category,
        hard=hard,
    )


def _effective_command_line(relative_path: str, line: str) -> str:
    suffix = relative_path.rsplit(".", 1)[-1].lower()
    if suffix not in {"desktop", "service", "socket", "timer"}:
        return line
    match = re.match(
        r"\s*(?:Exec|ExecCondition|ExecReload|ExecStart|ExecStartPost|ExecStartPre|"
        r"ExecStop|ExecStopPost)\s*=\s*[-+!:@]*\s*(.*)",
        line,
        re.IGNORECASE,
    )
    return match.group(1) if match else line


def _directive_has_inline_shell(relative_path: str, original_line: str, command_line: str) -> bool:
    suffix = relative_path.rsplit(".", 1)[-1].lower()
    if suffix not in {"desktop", "service", "socket", "timer"} or command_line == original_line:
        return True
    segments = _shell_segments(command_line)
    if not segments:
        return False
    command_at = _command_index(segments[0])
    if command_at is None:
        return False
    command = segments[0][command_at].rsplit("/", 1)[-1].lower()
    return command in {"bash", "dash", "fish", "ksh", "sh", "zsh"} and "-c" in segments[0]


_URL = re.compile(r"(?:(?:git|svn|hg|bzr)\+)?https?://[^\s'\"()]+", re.IGNORECASE)
_SOURCE_BLOCK = re.compile(
    r"(?ims)^\s*source(?:_[a-z0-9_]+)?\s*=\s*\((.*?)\)", re.IGNORECASE | re.DOTALL
)
_CHECKSUM_SKIP = re.compile(
    r"(?ims)^\s*(sha(?:1|224|256|384|512)sums|b2sums|md5sums)\s*=\s*\((.*?)\)"
)
_LITERAL_ASSIGNMENT = re.compile(
    r"(?m)^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?:'([^'\n]*)'|\"([^\"\n]*)\"|([^\s#()]+))\s*(?:#.*)?$"
)
_VARIABLE_REFERENCE = re.compile(r"\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?")


def _literal_assignments(text: str) -> dict[str, str]:
    return {
        match.group(1): next(value for value in match.groups()[1:] if value is not None)
        for match in _LITERAL_ASSIGNMENT.finditer(text)
    }


def _expand_literal_references(value: str, literals: dict[str, str]) -> str:
    expanded = value
    for _ in range(8):
        updated = _VARIABLE_REFERENCE.sub(
            lambda match: literals.get(match.group(1), match.group(0)), expanded
        )
        if updated == expanded:
            break
        expanded = updated
    return expanded


def extract_install_hook_names(pkgbuild: str) -> set[str]:
    literals = _literal_assignments(pkgbuild)
    hooks: set[str] = set()
    for match in _LITERAL_ASSIGNMENT.finditer(pkgbuild):
        if match.group(1) != "install":
            continue
        value = next(item for item in match.groups()[1:] if item is not None)
        expanded = _expand_literal_references(value, literals).removeprefix("./")
        if (
            expanded
            and "$" not in expanded
            and "`" not in expanded
            and not expanded.startswith("/")
        ):
            hooks.add(expanded)
    return hooks


def analyze_rules(files: list[InspectedFile], metadata: PackageMetadata) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[tuple[str, str, int]] = set()
    pkgbuild = next((f.content for f in files if f.relative_path == "PKGBUILD"), "")
    install_hooks = extract_install_hook_names(pkgbuild)
    for inspected in files:
        is_install = (
            inspected.relative_path.endswith(".install") or inspected.relative_path in install_hooks
        )
        lines = _logical_shell_lines(inspected.content)
        downloads: list[tuple[int, str, str]] = []
        credential_variables: dict[str, tuple[int, str]] = {}
        for logical in lines:
            number = logical.number
            effective_line = _effective_command_line(inspected.relative_path, logical.text)
            inline_shell = _directive_has_inline_shell(
                inspected.relative_path, logical.text, effective_line
            )
            line = _strip_shell_comment(effective_line)
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            nested_commands = _command_substitutions(line)
            segments = [
                segment
                for analyzable in [line, *nested_commands]
                for segment in _shell_segments(analyzable)
            ]
            parsed = [_path_uses(segment) for segment in segments]
            commands = [command for command, _ in parsed if command]
            inert_output = bool(commands) and all(
                command in _PASSIVE_TEXT_COMMANDS for command in commands
            )

            if commands and not inert_output:
                for rule in RULES:
                    if not inline_shell and rule.rule_id in _SHELL_SYNTAX_RULES:
                        continue
                    raw_rule_inputs = [line, *nested_commands]
                    rule_inputs = (
                        raw_rule_inputs
                        if rule.rule_id in {"embedded-private-key", "large-encoded"}
                        else [_mask_quoted_assignment_data(value) for value in raw_rule_inputs]
                    )
                    if not any(rule.pattern.search(value) for value in rule_inputs):
                        continue
                    severity = rule.severity
                    description = rule.description
                    if rule.rule_id == "setuid" and re.search(
                        r"\$(?:\{)?pkgdir(?:\})?", line, re.IGNORECASE
                    ):
                        description = (
                            "Stages a set-ID bit or Linux capability in package contents; "
                            "the property remains security-sensitive after installation."
                        )
                    if is_install and rule.install_boost and severity == Risk.MEDIUM:
                        severity = Risk.HIGH
                    key = (rule.rule_id, inspected.relative_path, number)
                    if key not in seen:
                        findings.append(
                            Finding(
                                severity,
                                rule.rule_id,
                                inspected.relative_path,
                                number,
                                stripped[:500],
                                description,
                                rule.category,
                                hard=rule.hard,
                            )
                        )
                        seen.add(key)

            for _, uses in parsed:
                for use in uses:
                    finding = _path_finding(
                        use,
                        inspected.relative_path,
                        number,
                        stripped,
                        metadata,
                        is_install=is_install,
                    )
                    if finding is None:
                        continue
                    key = (finding.rule_id, inspected.relative_path, number)
                    if key not in seen:
                        findings.append(finding)
                        seen.add(key)

            assignment = re.match(r"\s*([A-Za-z_][A-Za-z0-9_]*)\s*=", line)
            if assignment:
                variable = assignment.group(1)
                sensitive_read = any(
                    use.operation == "read"
                    and (
                        "/.ssh/id_" in use.path.lower()
                        or "/.gnupg/private-keys" in use.path.lower()
                        or "/.aws/credentials" in use.path.lower()
                        or "/etc/shadow" in use.path.lower()
                    )
                    for _, uses in parsed
                    for use in uses
                )
                inherited_taint = any(
                    re.search(rf"\$(?:\{{{re.escape(name)}\}}|{re.escape(name)}\b)", line)
                    for name in credential_variables
                )
                if sensitive_read or inherited_taint:
                    credential_variables[variable] = (number, stripped[:500])
                else:
                    credential_variables.pop(variable, None)

            upload_command = re.search(
                r"\b(?:curl|wget)\b[^\n]*(?:-d\b|-F\b|-T\b|--data|--form|--upload-file)"
                r"|\b(?:nc|ncat|netcat|socat)\b",
                line,
                re.IGNORECASE,
            )
            if upload_command:
                for variable, (_, source_evidence) in credential_variables.items():
                    if not re.search(
                        rf"\$(?:\{{{re.escape(variable)}\}}|{re.escape(variable)}\b)", line
                    ):
                        continue
                    key = ("credential-variable-exfil", inspected.relative_path, number)
                    if key not in seen:
                        findings.append(
                            Finding(
                                Risk.CRITICAL,
                                "credential-variable-exfil",
                                inspected.relative_path,
                                number,
                                f"{source_evidence} ; {stripped}"[:500],
                                "Reads credential-sensitive data into a variable and transmits it over the network.",
                                "data-exfiltration",
                                hard=True,
                            )
                        )
                        seen.add(key)
                    break

            download = _DOWNLOAD_TO_FILE.search(line)
            if download and not inert_output:
                target = (download.group(1) or download.group(2)).strip("'\"")
                downloads.append((number, target, stripped[:500]))

        for download_line, target, evidence in downloads:
            token = re.escape(target)
            basename = re.escape(target.rsplit("/", 1)[-1])
            execution = re.compile(
                rf"(?:\b(?:ba|z|fi)?sh\s+[^\n]*(?:{token}|{basename})|\bchmod\b[^\n]*\+x[^\n]*(?:{token}|{basename})|(?:^|[;&|]\s*)\./{basename}\b)",
                re.IGNORECASE,
            )
            for later in lines:
                if later.number <= download_line or later.number > download_line + 8:
                    continue
                if execution.search(_strip_shell_comment(later.text)):
                    findings.append(
                        Finding(
                            Risk.HIGH,
                            "remote-download-exec",
                            inspected.relative_path,
                            later.number,
                            f"{evidence} ; {later.text.strip()}"[:500],
                            "Downloads a remote file and executes it shortly afterward.",
                            "remote-code-execution",
                            hard=True,
                        )
                    )
                    break

    for match in _CHECKSUM_SKIP.finditer(pkgbuild):
        if not re.search(r"\bSKIP\b", match.group(2), re.IGNORECASE):
            continue
        line_number = pkgbuild.count("\n", 0, match.start()) + 1
        description = (
            "VCS package uses a skipped source checksum."
            if metadata.vcs_package
            else "A source integrity checksum is skipped."
        )
        severity = Risk.INFO if metadata.vcs_package else Risk.LOW
        findings.append(
            Finding(
                severity,
                "skipped-checksum",
                "PKGBUILD",
                line_number,
                match.group(0)[:500],
                description,
                "source-integrity",
            )
        )
    if metadata.url and metadata.source_domains:
        from urllib.parse import urlparse

        upstream = (urlparse(metadata.url).hostname or "").lower()
        github_hosts = {"github.com", "raw.githubusercontent.com", "objects.githubusercontent.com"}
        if upstream == "github.com":
            for domain in metadata.source_domains:
                if domain not in github_hosts:
                    findings.append(
                        Finding(
                            Risk.LOW,
                            "source-host-mismatch",
                            "PKGBUILD",
                            0,
                            domain,
                            "A declared source is hosted outside the package's stated GitHub upstream; verify the mirror or release host.",
                            "source-integrity",
                        )
                    )
    return findings


def extract_source_data(pkgbuild: str) -> tuple[list[str], list[str]]:
    from urllib.parse import urlparse

    urls: list[str] = []
    domains: list[str] = []
    first_function = re.search(r"(?m)^\s*[A-Za-z_][A-Za-z0-9_]*\s*\(\s*\)\s*\{", pkgbuild)
    assignment_region = pkgbuild[: first_function.start()] if first_function else pkgbuild
    literals = _literal_assignments(assignment_region)

    for block in _SOURCE_BLOCK.finditer(pkgbuild):
        expanded_block = _expand_literal_references(block.group(1), literals)
        for match in _URL.finditer(expanded_block):
            url = match.group(0).rstrip(".,;]")
            if url not in urls:
                urls.append(url)
            parsed = urlparse(re.sub(r"^(?:git|svn|hg|bzr)\+", "", url, flags=re.IGNORECASE))
            if parsed.hostname and parsed.hostname.lower() not in domains:
                domains.append(parsed.hostname.lower())
    return urls, domains
