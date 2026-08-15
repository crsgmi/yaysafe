from __future__ import annotations

from pathlib import Path

import pytest

from yaysafe.config import (
    ConfigError,
    cache_dir,
    config_path,
    ensure_default_config,
    load_config,
    redacted_config_text,
    save_llm_selection,
    select_editor,
)


def test_config_creation_does_not_overwrite(tmp_path: Path) -> None:
    path = tmp_path / "config.toml"
    ensure_default_config(path)
    original = path.read_text()
    ensure_default_config(path)
    assert path.read_text() == original
    assert path.stat().st_mode & 0o777 == 0o600


def test_insecure_or_symlinked_configuration_is_rejected(tmp_path: Path) -> None:
    permissive = tmp_path / "permissive.toml"
    permissive.write_text("[llm]\n")
    permissive.chmod(0o644)
    with pytest.raises(ConfigError, match="permissions are too open"):
        load_config(permissive, create=False)

    private = tmp_path / "private.toml"
    private.write_text("[llm]\n")
    private.chmod(0o600)
    linked = tmp_path / "linked.toml"
    linked.symlink_to(private)
    with pytest.raises(ConfigError, match="regular file"):
        load_config(linked, create=False)


def test_config_parsing(tmp_path: Path) -> None:
    path = tmp_path / "config.toml"
    ensure_default_config(path)
    config = load_config(path)
    assert config.llm.provider == "lmstudio"
    assert config.llm.base_url == "http://127.0.0.1:1234/v1"
    assert config.llm.max_tokens == 2048
    assert config.llm.max_prompt_size == 65_536
    assert config.llm.reasoning_effort == "none"
    assert config.scanner.max_file_size == 262_144
    assert config.scanner.max_repository_size == 268_435_456
    assert config.policy.block_critical is True


def test_invalid_config(tmp_path: Path) -> None:
    path = tmp_path / "bad.toml"
    path.write_text("[llm]\ntimeout = 'forever'\n")
    with pytest.raises(ConfigError):
        load_config(path, create=False)


def test_invalid_llm_token_limit(tmp_path: Path) -> None:
    path = tmp_path / "bad-tokens.toml"
    path.write_text("[llm]\nmax_tokens = 0\n")
    with pytest.raises(ConfigError):
        load_config(path, create=False)


@pytest.mark.parametrize("timeout", ["nan", "inf", "86401"])
def test_non_finite_or_extreme_timeout_is_rejected(timeout: str, tmp_path: Path) -> None:
    path = tmp_path / "bad-timeout.toml"
    path.write_text(f"[llm]\ntimeout = {timeout}\n")
    path.chmod(0o600)
    with pytest.raises(ConfigError, match="finite"):
        load_config(path, create=False)


def test_invalid_llm_prompt_limit(tmp_path: Path) -> None:
    path = tmp_path / "bad-prompt.toml"
    path.write_text("[llm]\nmax_prompt_size = 100\n")
    with pytest.raises(ConfigError):
        load_config(path, create=False)


def test_invalid_reasoning_effort(tmp_path: Path) -> None:
    path = tmp_path / "bad-reasoning.toml"
    path.write_text('[llm]\nreasoning_effort = "extreme"\n')
    with pytest.raises(ConfigError):
        load_config(path, create=False)


def test_invalid_llm_provider(tmp_path: Path) -> None:
    path = tmp_path / "bad-provider.toml"
    path.write_text('[llm]\nprovider = "mystery-cloud"\n')
    path.chmod(0o600)
    with pytest.raises(ConfigError, match="llm.provider"):
        load_config(path, create=False)


def test_config_without_provider_remains_backward_compatible(tmp_path: Path) -> None:
    path = tmp_path / "old-config.toml"
    path.write_text('[llm]\nbase_url = "http://localhost:9999/v1"\n')
    path.chmod(0o600)
    config = load_config(path, create=False)
    assert config.llm.provider == "lmstudio"
    assert config.llm.base_url == "http://localhost:9999/v1"


def test_xdg_paths(tmp_path: Path) -> None:
    env = {
        "HOME": "/ignored",
        "XDG_CONFIG_HOME": str(tmp_path / "cfg"),
        "XDG_CACHE_HOME": str(tmp_path / "cache"),
    }
    assert config_path(env) == tmp_path / "cfg/yaysafe/config.toml"
    assert cache_dir(env) == tmp_path / "cache/yaysafe"


def test_relative_xdg_paths_are_ignored() -> None:
    env = {
        "HOME": "/home/example",
        "XDG_CONFIG_HOME": "relative-config",
        "XDG_CACHE_HOME": "relative-cache",
    }
    assert config_path(env) == Path("/home/example/.config/yaysafe/config.toml")
    assert cache_dir(env) == Path("/home/example/.cache/yaysafe")


@pytest.mark.parametrize(
    "endpoint",
    [
        "http://",
        "ftp://localhost/v1",
        "http://user:password@localhost/v1",
        "http://x/v1?q=1",
        "http://x/v1?",
        "http://x:99999/v1",
    ],
)
def test_invalid_llm_endpoint(endpoint: str, tmp_path: Path) -> None:
    path = tmp_path / "invalid-endpoint.toml"
    path.write_text(f'[llm]\nbase_url = "{endpoint}"\n')
    with pytest.raises(ConfigError):
        load_config(path, create=False)


def test_editor_selection_prefers_visual(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "shutil.which", lambda name: f"/usr/bin/{name}" if name == "myedit" else None
    )
    assert select_editor({"VISUAL": "myedit --wait", "EDITOR": "other"}) == ["myedit", "--wait"]


def test_printed_config_never_exposes_api_key(tmp_path: Path) -> None:
    path = tmp_path / "config.toml"
    path.write_text(
        """[llm]
api_key = "very-secret"
[scanner]
[policy]
[ui]
"""
    )
    path.chmod(0o600)
    shown = redacted_config_text(path)
    assert "very-secret" not in shown
    assert 'api_key = "<redacted>"' in shown


def test_llm_selection_preserves_other_configuration(tmp_path: Path) -> None:
    path = tmp_path / "config.toml"
    ensure_default_config(path)
    original = path.read_text().replace(
        "confirm_high = true", "# keep this policy comment\nconfirm_high = false"
    )
    path.write_text(original)
    save_llm_selection(
        "https://api.openai.com/v1",
        "model-two",
        path,
        provider="openai",
        api_key="new-secret",
    )
    saved = path.read_text()
    config = load_config(path)
    assert config.llm.provider == "openai"
    assert config.llm.base_url == "https://api.openai.com/v1"
    assert config.llm.api_key == "new-secret"
    assert config.llm.model == "model-two"
    assert config.llm.enabled is True
    assert config.policy.confirm_high is False
    assert "# keep this policy comment" in saved
    assert 'api_key = "new-secret"' in saved
    assert path.stat().st_mode & 0o777 == 0o600
