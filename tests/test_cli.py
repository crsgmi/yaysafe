from __future__ import annotations

import json
import subprocess
import sys
from io import StringIO
from pathlib import Path

import pytest

from yaysafe.cli import PROVIDER_PRESETS, command_cache, handle_yay, main
from yaysafe.config import Config, UIConfig, load_config
from yaysafe.scanner import scan_repository
from yaysafe.ui import UI
from yaysafe.verdict import combine_results
from yaysafe.yay import (
    classify_args,
    isolated_yay_environment,
    with_reviewed_builddir,
    yay_option_value,
)


def test_cli_argument_passthrough_classification() -> None:
    remove = classify_args(["-R", "package"])
    assert remove.install is False
    search = classify_args(["-Ss", "query"])
    assert search.install is False
    install = classify_args(["-S", "package", "--needed"])
    assert install.install is True
    assert install.targets == ["package"]
    upgrade = classify_args(["-Syu"])
    assert upgrade.install is True and upgrade.sysupgrade is True
    download_only = classify_args(["-Sw", "package"])
    assert download_only.install is True
    alternate_root = classify_args(["-S", "-r", "/mnt/test", "package"])
    assert alternate_root.targets == ["package"]
    implicit = classify_args(["package"])
    assert implicit.targets == ["package"]
    assert implicit.explicit_operation is False


def test_llm_provider_presets_have_expected_defaults() -> None:
    presets = {preset.key: preset for preset in PROVIDER_PRESETS}
    assert presets["lmstudio"].base_url == "http://127.0.0.1:1234/v1"
    assert presets["ollama"].base_url == "http://127.0.0.1:11434/v1"
    assert presets["openai"].base_url == "https://api.openai.com/v1"
    assert presets["anthropic"].base_url == "https://api.anthropic.com/v1"
    assert presets["openai"].requires_api_key is True
    assert presets["anthropic"].requires_api_key is True


def test_security_options_are_inserted_before_separator() -> None:
    args = with_reviewed_builddir(["-S", "--", "odd-name"], "/tmp/reviewed")
    assert args == [
        "-S",
        "--builddir",
        "/tmp/reviewed",
        "--noredownload",
        "--editmenu=false",
        "--debug=false",
        "--",
        "odd-name",
    ]


def test_user_cannot_override_reviewed_build_directory_or_redownload_policy() -> None:
    args = with_reviewed_builddir(
        [
            "-S",
            "--builddir=/tmp/unreviewed",
            "--redownloadall",
            "--builddir",
            "/tmp/also-unreviewed",
            "package",
        ],
        "/tmp/reviewed",
    )
    assert args == [
        "-S",
        "package",
        "--builddir",
        "/tmp/reviewed",
        "--noredownload",
        "--editmenu=false",
        "--debug=false",
    ]


def test_isolated_yay_config_preserves_options_but_disables_mutation(tmp_path) -> None:
    environment = isolated_yay_environment(
        {"cleanmenu": False, "editmenu": True, "redownload": "all"},
        tmp_path / "config",
        "/tmp/reviewed",
    )
    saved = (tmp_path / "config/yay/config.json").read_text()
    assert '"cleanmenu": false' in saved
    assert '"editmenu": false' in saved
    assert '"redownload": "no"' in saved
    assert '"buildDir": "/tmp/reviewed"' in saved
    assert '"debug": false' in saved
    assert '"gitflags": ""' in saved
    assert (tmp_path / "config/yay/init.lua").read_text().startswith("-- yaysafe")
    wrapper = tmp_path / "config/git-wrapper"
    assert wrapper.stat().st_mode & 0o777 == 0o700
    assert "core.hooksPath=/dev/null" in wrapper.read_text()
    assert '"clone", "fetch", "pull", "submodule"' in wrapper.read_text()
    assert '"clean", "merge", "reset"' in wrapper.read_text()
    assert environment["XDG_CONFIG_HOME"] == str(tmp_path / "config")
    assert environment["GIT_CONFIG_NOSYSTEM"] == "1"
    blocked = subprocess.run(
        [str(wrapper), "clone", "https://example.invalid/repo"],
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )
    assert blocked.returncode == 78
    assert "unreviewed Git content" in blocked.stderr
    assert (
        subprocess.run([str(wrapper), "reset", "--hard"], env=environment, check=False).returncode
        == 0
    )


def test_last_yay_endpoint_option_wins_before_target_separator() -> None:
    args = [
        "-S",
        "--aururl=first.invalid",
        "--aururl",
        "https://second.invalid",
        "--",
        "package",
    ]
    assert yay_option_value(args, "--aururl") == "https://second.invalid"


def test_reviewed_handoff_uses_isolated_yay_configuration(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}
    monkeypatch.setattr("yaysafe.cli.aur_targets", lambda invocation: ["demo"])
    monkeypatch.setattr(
        "yaysafe.cli.yay_current_config",
        lambda: {
            "aururl": "https://aur.archlinux.org",
            "aurrpcurl": "https://aur.archlinux.org/rpc?",
            "cleanmenu": True,
        },
    )

    def fake_analysis(names, destination, config, ui, **kwargs):
        repo = destination / "demo"
        repo.mkdir()
        (repo / "PKGBUILD").write_text("pkgname=demo\npkgver=1\npkgrel=1\n")
        static = scan_repository(repo, "demo", config.scanner)
        verdict = combine_results("demo", static, None, llm_requested=False)
        return [(verdict, static)]

    def fake_run(args, *, env=None):
        captured["args"] = args
        assert env is not None
        config_root = Path(env["XDG_CONFIG_HOME"])
        captured["config"] = json.loads(
            (config_root / "yay/config.json").read_text(encoding="utf-8")
        )
        captured["lua"] = (config_root / "yay/init.lua").read_text(encoding="utf-8")
        return 0

    monkeypatch.setattr("yaysafe.cli._retrieve_and_analyze", fake_analysis)
    monkeypatch.setattr("yaysafe.cli.run_yay", fake_run)
    output = StringIO()
    assert handle_yay(["-S", "demo"], Config(), UI(UIConfig(color=False), out=output)) == 0
    assert "--noredownload" in captured["args"]
    assert "--editmenu=false" in captured["args"]
    assert captured["config"]["editmenu"] is False
    assert str(captured["lua"]).startswith("-- yaysafe")


def test_passthrough_keeps_original_array(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    captured = []
    monkeypatch.setattr("yaysafe.cli.run_yay", lambda args: captured.append(args) or 7)
    assert main(["-R", "some package", "--noconfirm"]) == 7
    assert captured == [["-R", "some package", "--noconfirm"]]


def test_redirected_prompt_output_stays_line_oriented(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
    monkeypatch.setattr("sys.stdin", StringIO("n\n"))

    ui = UI(UIConfig(color=False), out=sys.stdout)
    assert command_cache(["clear"], ui) == 0

    output = capsys.readouterr().out
    assert "==> \n:: Cache unchanged." in output
    assert "==> ::" not in output


def test_interactive_llm_model_selection(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    answers = iter(["1", "http://127.0.0.1:1234", "2"])
    monkeypatch.setattr("builtins.input", lambda prompt="": next(answers))

    class FakeClient:
        def list_models(self) -> list[str]:
            return ["small-model", "security-model"]

    def fake_client(config):
        assert config.provider == "lmstudio"
        assert config.base_url == "http://127.0.0.1:1234/v1"
        assert config.api_key == "lm-studio"
        return FakeClient()

    monkeypatch.setattr("yaysafe.cli.create_llm_client", fake_client)
    assert main(["config", "llm"]) == 0
    config = load_config(tmp_path / "yaysafe/config.toml")
    assert config.llm.provider == "lmstudio"
    assert config.llm.base_url == "http://127.0.0.1:1234/v1"
    assert config.llm.model == "security-model"


def test_openai_setup_uses_preset_and_hidden_key(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    answers = iter(["3", "", "1"])
    monkeypatch.setattr("builtins.input", lambda prompt="": next(answers))
    monkeypatch.setattr("yaysafe.cli.getpass.getpass", lambda prompt="": "sk-test-secret")

    class FakeClient:
        def list_models(self) -> list[str]:
            return ["gpt-test"]

    def fake_client(config):
        assert config.provider == "openai"
        assert config.base_url == "https://api.openai.com/v1"
        assert config.api_key == "sk-test-secret"
        return FakeClient()

    monkeypatch.setattr("yaysafe.cli.create_llm_client", fake_client)
    assert main(["config", "llm"]) == 0

    config = load_config(tmp_path / "yaysafe/config.toml")
    assert config.llm.provider == "openai"
    assert config.llm.api_key == "sk-test-secret"
    assert config.llm.model == "gpt-test"
    assert "sk-test-secret" not in capsys.readouterr().out


def test_ctrl_c_handling(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("yaysafe.cli._run", lambda argv: (_ for _ in ()).throw(KeyboardInterrupt()))
    assert main([]) == 130


def test_root_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("os.geteuid", lambda: 0)
    assert main(["--version"]) == 1
