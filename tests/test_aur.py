from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from yaysafe.aur import (
    AURClient,
    AURError,
    AURPackage,
    normalize_target,
    parse_srcinfo_dependencies,
)


def test_dependency_parsing_without_execution(tmp_path: Path) -> None:
    srcinfo = tmp_path / ".SRCINFO"
    srcinfo.write_text(
        "pkgbase = demo\n"
        "\tdepends = runtime>=2\n"
        "\tmakedepends_x86_64 = compiler\n"
        "\tcheckdepends = tester\n"
    )
    assert parse_srcinfo_dependencies(srcinfo) == ["runtime>=2", "compiler", "tester"]
    assert normalize_target("aur/demo>=1") == "demo"


def test_srcinfo_symlink_is_rejected(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.write_text("depends = secret")
    link = tmp_path / ".SRCINFO"
    link.symlink_to(outside)
    with pytest.raises(AURError):
        parse_srcinfo_dependencies(link)


def test_clone_disables_local_git_hooks_filters_and_external_protocols(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    captured: dict[str, object] = {}
    monkeypatch.setenv("GIT_CONFIG_PARAMETERS", "'filter.hostile.clean=!run-me'")

    def fake_run(command, **kwargs):
        captured["command"] = command
        captured["env"] = kwargs["env"]
        target = tmp_path / "demo"
        (target / ".git").mkdir(parents=True)
        (target / "PKGBUILD").write_text("pkgname=demo\n")
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr("yaysafe.aur.subprocess.run", fake_run)
    root = AURClient().clone(AURPackage("demo", "demo"), tmp_path)

    assert root == tmp_path / "demo"
    command = captured["command"]
    assert isinstance(command, list)
    assert "core.hooksPath=/dev/null" in command
    assert "protocol.ext.allow=never" in command
    environment = captured["env"]
    assert isinstance(environment, dict)
    assert "GIT_CONFIG_PARAMETERS" not in environment
    assert environment["GIT_CONFIG_NOSYSTEM"] == "1"
    assert environment["GIT_CONFIG_GLOBAL"] == "/dev/null"


def test_legacy_yay_rpc_endpoint_shape_is_supported() -> None:
    requested: list[str] = []

    def fetch(url: str, timeout: float):
        requested.append(url)
        return {"results": []}

    client = AURClient(rpc_url="https://aur.example/rpc?", fetch_json=fetch)
    client.info(["demo"])
    assert requested == ["https://aur.example/rpc?v=5&type=info&arg%5B%5D=demo"]


@pytest.mark.parametrize(
    "kwargs",
    [
        {"aur_url": "file:///tmp/aur"},
        {"rpc_url": "https://user:password@aur.example/rpc?"},
    ],
)
def test_unsafe_custom_aur_endpoints_are_rejected(kwargs: dict[str, str]) -> None:
    with pytest.raises(AURError):
        AURClient(**kwargs)


@pytest.mark.parametrize("package_base", ["..", ".hidden", "../escape", "name/path"])
def test_unsafe_package_base_cannot_escape_destination(package_base: str, tmp_path: Path) -> None:
    with pytest.raises(AURError, match="unsafe package base"):
        AURClient().clone(AURPackage("demo", package_base), tmp_path)
