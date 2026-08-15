from __future__ import annotations

import math
import os
import re
import shlex
import shutil
import subprocess
import tempfile
import tomllib
import urllib.parse
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

DEFAULT_CONFIG = """[llm]
enabled = true
provider = "lmstudio"
# LM Studio's default local OpenAI-compatible endpoint.
base_url = "http://127.0.0.1:1234/v1"
api_key = "lm-studio"
# Run `yaysafe config llm` to discover and select a loaded model.
model = ""
# Maximum seconds without any response/stream activity. This is not a total generation deadline.
timeout = 300
# Maximum tokens generated for one analysis response.
max_tokens = 2048
# Maximum UTF-8 bytes for the complete security prompt. Increase only when the
# selected model has enough context for the prompt plus max_tokens of output.
max_prompt_size = 65536
# Use "" to omit this option for endpoints that do not support reasoning control.
reasoning_effort = "none"

[scanner]
enabled = true
max_file_size = 262144
max_total_prompt_size = 1048576
max_repository_size = 268435456

[policy]
block_critical = true
confirm_high = true
confirm_medium = true
allow_low = true
allow_info = true
fail_closed = false

[ui]
color = true
show_confidence = true
show_sources = true
"""


class ConfigError(ValueError):
    pass


@dataclass(slots=True)
class LLMConfig:
    enabled: bool = True
    provider: str = "lmstudio"
    base_url: str = "http://127.0.0.1:1234/v1"
    api_key: str = "lm-studio"
    model: str = ""
    timeout: float = 300.0
    max_tokens: int = 2048
    max_prompt_size: int = 65_536
    reasoning_effort: str = "none"


@dataclass(slots=True)
class ScannerConfig:
    enabled: bool = True
    max_file_size: int = 262_144
    max_total_prompt_size: int = 1_048_576
    max_repository_size: int = 268_435_456


@dataclass(slots=True)
class PolicyConfig:
    block_critical: bool = True
    confirm_high: bool = True
    confirm_medium: bool = True
    allow_low: bool = True
    allow_info: bool = True
    fail_closed: bool = False


@dataclass(slots=True)
class UIConfig:
    color: bool = True
    show_confidence: bool = True
    show_sources: bool = True


@dataclass(slots=True)
class Config:
    llm: LLMConfig = field(default_factory=LLMConfig)
    scanner: ScannerConfig = field(default_factory=ScannerConfig)
    policy: PolicyConfig = field(default_factory=PolicyConfig)
    ui: UIConfig = field(default_factory=UIConfig)


def config_path(env: Mapping[str, str] | None = None) -> Path:
    values = os.environ if env is None else env
    base = values.get("XDG_CONFIG_HOME")
    root = _xdg_root(base, values, ".config")
    return root / "yaysafe" / "config.toml"


def cache_dir(env: Mapping[str, str] | None = None) -> Path:
    values = os.environ if env is None else env
    base = values.get("XDG_CACHE_HOME")
    root = _xdg_root(base, values, ".cache")
    return root / "yaysafe"


def _xdg_root(base: str | None, values: Mapping[str, str], fallback: str) -> Path:
    # The XDG Base Directory specification requires these values to be absolute.
    if base:
        candidate = Path(base).expanduser()
        if candidate.is_absolute():
            return candidate
    home = Path(values.get("HOME", str(Path.home()))).expanduser()
    if not home.is_absolute():
        home = Path.home()
    return home / fallback


def ensure_default_config(path: Path | None = None) -> Path:
    target = path or config_path()
    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if target.parent.is_symlink() or not target.parent.is_dir():
        raise ConfigError(f"unsafe configuration directory: {target.parent}")
    target.parent.chmod(0o700)
    try:
        with target.open("x", encoding="utf-8") as handle:
            handle.write(DEFAULT_CONFIG)
        target.chmod(0o600)
    except FileExistsError:
        if target.is_symlink() or not target.is_file():
            raise ConfigError(f"configuration must be a regular file: {target}")
    return target


def _validate_config_permissions(target: Path) -> None:
    if target.is_symlink() or not target.is_file():
        raise ConfigError(f"configuration must be a regular file: {target}")
    try:
        stat = target.stat(follow_symlinks=False)
    except OSError as exc:
        raise ConfigError(f"cannot inspect configuration: {exc}") from exc
    if stat.st_uid != os.geteuid():
        raise ConfigError("configuration must be owned by the current user")
    if stat.st_mode & 0o077:
        raise ConfigError(f"configuration permissions are too open; run: chmod 600 {target}")


def _table(data: dict[str, Any], key: str) -> dict[str, Any]:
    value = data.get(key, {})
    if not isinstance(value, dict):
        raise ConfigError(f"[{key}] must be a TOML table")
    return value


def _get(table: dict[str, Any], key: str, expected: type[Any], default: Any) -> Any:
    value = table.get(key, default)
    if expected is float and isinstance(value, (int, float)) and not isinstance(value, bool):
        return float(value)
    if expected is int and isinstance(value, int) and not isinstance(value, bool):
        return value
    if not isinstance(value, expected):
        raise ConfigError(f"{key} must be {expected.__name__}")
    return value


def parse_config(data: dict[str, Any]) -> Config:
    llm, scanner, policy, ui = (_table(data, key) for key in ("llm", "scanner", "policy", "ui"))
    defaults = Config()
    cfg = Config(
        llm=LLMConfig(
            enabled=_get(llm, "enabled", bool, True),
            provider=_get(llm, "provider", str, defaults.llm.provider),
            base_url=_get(llm, "base_url", str, defaults.llm.base_url),
            api_key=_get(llm, "api_key", str, defaults.llm.api_key),
            model=_get(llm, "model", str, ""),
            timeout=_get(llm, "timeout", float, 300.0),
            max_tokens=_get(llm, "max_tokens", int, 2048),
            max_prompt_size=_get(llm, "max_prompt_size", int, 65_536),
            reasoning_effort=_get(llm, "reasoning_effort", str, "none"),
        ),
        scanner=ScannerConfig(
            enabled=_get(scanner, "enabled", bool, True),
            max_file_size=_get(scanner, "max_file_size", int, 262_144),
            max_total_prompt_size=_get(scanner, "max_total_prompt_size", int, 1_048_576),
            max_repository_size=_get(scanner, "max_repository_size", int, 268_435_456),
        ),
        policy=PolicyConfig(
            **{
                name: _get(policy, name, bool, getattr(PolicyConfig(), name))
                for name in PolicyConfig.__dataclass_fields__
            }
        ),
        ui=UIConfig(
            **{
                name: _get(ui, name, bool, getattr(UIConfig(), name))
                for name in UIConfig.__dataclass_fields__
            }
        ),
    )
    try:
        endpoint = urllib.parse.urlsplit(cfg.llm.base_url)
        hostname = endpoint.hostname
        _ = endpoint.port
    except ValueError as exc:
        raise ConfigError("llm.base_url is not a valid URL") from exc
    if (
        endpoint.scheme not in {"http", "https"}
        or not hostname
        or endpoint.username is not None
        or endpoint.password is not None
        or "?" in cfg.llm.base_url
        or "#" in cfg.llm.base_url
        or endpoint.query
        or endpoint.fragment
    ):
        raise ConfigError(
            "llm.base_url must be an http(s) URL without credentials, query, or fragment"
        )
    if cfg.llm.provider not in {
        "lmstudio",
        "ollama",
        "openai",
        "anthropic",
        "openai-compatible",
    }:
        raise ConfigError(
            "llm.provider must be lmstudio, ollama, openai, anthropic, or openai-compatible"
        )
    if not math.isfinite(cfg.llm.timeout) or not 0 < cfg.llm.timeout <= 86_400:
        raise ConfigError("llm.timeout must be finite and between 0 and 86400 seconds")
    if "\r" in cfg.llm.api_key or "\n" in cfg.llm.api_key:
        raise ConfigError("llm.api_key must not contain line breaks")
    if cfg.llm.max_tokens < 256:
        raise ConfigError("llm.max_tokens must be at least 256")
    if cfg.llm.max_tokens > 65_536:
        raise ConfigError("llm.max_tokens must not exceed 65536")
    if cfg.llm.max_prompt_size < 16_384:
        raise ConfigError("llm.max_prompt_size must be at least 16384")
    if cfg.llm.max_prompt_size > 16 * 1024 * 1024:
        raise ConfigError("llm.max_prompt_size must not exceed 16777216")
    if cfg.llm.reasoning_effort not in {"", "none", "low", "medium", "high"}:
        raise ConfigError("llm.reasoning_effort must be none, low, medium, high, or empty")
    if cfg.scanner.max_file_size < 1024:
        raise ConfigError("scanner.max_file_size must be at least 1024")
    if cfg.scanner.max_total_prompt_size < cfg.scanner.max_file_size:
        raise ConfigError("scanner.max_total_prompt_size must be at least max_file_size")
    if cfg.scanner.max_repository_size < cfg.scanner.max_total_prompt_size:
        raise ConfigError("scanner.max_repository_size must be at least max_total_prompt_size")
    if cfg.scanner.max_repository_size > 4 * 1024 * 1024 * 1024:
        raise ConfigError("scanner.max_repository_size must not exceed 4294967296")
    return cfg


def load_config(path: Path | None = None, *, create: bool = True) -> Config:
    target = path or config_path()
    if create:
        ensure_default_config(target)
    try:
        _validate_config_permissions(target)
        with target.open("rb") as handle:
            return parse_config(tomllib.load(handle))
    except FileNotFoundError as exc:
        raise ConfigError(f"configuration not found: {target}") from exc
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"invalid TOML in {target}: {exc}") from exc
    except OSError as exc:
        raise ConfigError(f"cannot read configuration: {exc}") from exc


def select_editor(env: Mapping[str, str] | None = None) -> list[str] | None:
    values = os.environ if env is None else env
    for variable in ("VISUAL", "EDITOR"):
        if values.get(variable):
            try:
                command = shlex.split(values[variable])
            except ValueError:
                continue
            if command and shutil.which(command[0]):
                return command
    for candidate in ("nano", "vim", "vi"):
        path = shutil.which(candidate)
        if path:
            return [path]
    return None


def edit_config(path: Path | None = None) -> int:
    target = ensure_default_config(path)
    editor = select_editor()
    if not editor:
        raise ConfigError("no editor found; set $VISUAL or $EDITOR")
    return subprocess.run([*editor, str(target)], check=False).returncode


def save_llm_selection(
    base_url: str,
    model: str,
    path: Path | None = None,
    *,
    provider: str | None = None,
    api_key: str | None = None,
) -> Path:
    """Atomically update an LLM selection while preserving unrelated configuration."""
    target = ensure_default_config(path)
    if not model.strip():
        raise ConfigError("llm.model cannot be empty after model selection")
    try:
        original = target.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigError(f"cannot read configuration: {exc}") from exc
    values = {
        "base_url": json_string(base_url.rstrip("/")),
        "model": json_string(model),
        "enabled": "true",
    }
    if provider is not None:
        values["provider"] = json_string(provider)
    if api_key is not None:
        values["api_key"] = json_string(api_key)
    updated = _replace_table_values(original, "llm", values)
    try:
        parse_config(tomllib.loads(updated))
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"updated configuration would be invalid: {exc}") from exc
    fd, raw_temp = tempfile.mkstemp(prefix=".config-", suffix=".tmp", dir=target.parent)
    temporary = Path(raw_temp)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(updated)
            handle.flush()
            os.fsync(handle.fileno())
        temporary.chmod(0o600)
        temporary.replace(target)
    except OSError as exc:
        raise ConfigError(f"cannot save configuration: {exc}") from exc
    finally:
        temporary.unlink(missing_ok=True)
    return target


def _replace_table_values(text: str, table: str, values: dict[str, str]) -> str:
    lines = text.splitlines(keepends=True)
    header = re.compile(rf"^\s*\[{re.escape(table)}\]\s*(?:#.*)?$")
    any_header = re.compile(r"^\s*\[[^]]+\]")
    start = next((index for index, line in enumerate(lines) if header.match(line.rstrip("\n"))), -1)
    if start < 0:
        suffix = "" if not text or text.endswith("\n") else "\n"
        additions = "".join(f"{key} = {value}\n" for key, value in values.items())
        return f"{text}{suffix}\n[{table}]\n{additions}"
    end = next(
        (index for index in range(start + 1, len(lines)) if any_header.match(lines[index])),
        len(lines),
    )
    remaining = dict(values)
    key_pattern = re.compile(r"^(\s*)([A-Za-z0-9_-]+)\s*=")
    for index in range(start + 1, end):
        match = key_pattern.match(lines[index])
        if match and match.group(2) in remaining:
            key = match.group(2)
            newline = "\n" if lines[index].endswith("\n") else ""
            lines[index] = f"{match.group(1)}{key} = {remaining.pop(key)}{newline}"
    if remaining:
        insertions = [f"{key} = {value}\n" for key, value in remaining.items()]
        lines[end:end] = insertions
    return "".join(lines)


def redacted_config_text(path: Path | None = None) -> str:
    target = ensure_default_config(path)
    config = load_config(target, create=False)
    return f"""[llm]
enabled = {_toml_boolean(config.llm.enabled)}
provider = {json_string(config.llm.provider)}
base_url = {json_string(config.llm.base_url)}
api_key = "<redacted>"
model = {json_string(config.llm.model)}
timeout = {config.llm.timeout:g}
max_tokens = {config.llm.max_tokens}
max_prompt_size = {config.llm.max_prompt_size}
reasoning_effort = {json_string(config.llm.reasoning_effort)}

[scanner]
enabled = {_toml_boolean(config.scanner.enabled)}
max_file_size = {config.scanner.max_file_size}
max_total_prompt_size = {config.scanner.max_total_prompt_size}
max_repository_size = {config.scanner.max_repository_size}

[policy]
block_critical = {_toml_boolean(config.policy.block_critical)}
confirm_high = {_toml_boolean(config.policy.confirm_high)}
confirm_medium = {_toml_boolean(config.policy.confirm_medium)}
allow_low = {_toml_boolean(config.policy.allow_low)}
allow_info = {_toml_boolean(config.policy.allow_info)}
fail_closed = {_toml_boolean(config.policy.fail_closed)}

[ui]
color = {_toml_boolean(config.ui.color)}
show_confidence = {_toml_boolean(config.ui.show_confidence)}
show_sources = {_toml_boolean(config.ui.show_sources)}
"""


def _toml_boolean(value: bool) -> str:
    return "true" if value else "false"


def json_string(value: str) -> str:
    # JSON string syntax is valid TOML basic-string syntax and safely escapes newlines/quotes.
    import json

    return json.dumps(value, ensure_ascii=False)
