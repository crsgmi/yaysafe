from __future__ import annotations

import subprocess
from io import StringIO

import pytest

from yaysafe.aur import AURError, AURPackage, RetrievedPackage
from yaysafe.cache import ScanCache
from yaysafe.cli import EXIT_BLOCKED, EXIT_UNKNOWN, analyze_retrieved, handle_yay
from yaysafe.config import Config, UIConfig
from yaysafe.models import Risk
from yaysafe.scanner import ScanError, scan_repository
from yaysafe.ui import UI
from yaysafe.verdict import combine_results
from yaysafe.yay import YayError, aur_upgrades, classify_args, update_query_options


def _analysis_with_risks(risks: dict[str, Risk], seen: list[str] | None = None):
    def fake_analysis(names, destination, config, ui, **kwargs):
        if seen is not None:
            seen.extend(names)
        assert kwargs["use_llm"] is True
        assert kwargs["use_cache"] is True
        results = []
        for name in names:
            repository = destination / name
            repository.mkdir()
            (repository / "PKGBUILD").write_text(
                f"pkgname={name}\npkgver=2\npkgrel=1\n", encoding="utf-8"
            )
            static = scan_repository(repository, name, config.scanner)
            verdict = combine_results(name, static, None, llm_requested=False)
            verdict.risk = risks[name]
            verdict.confidence = None if risks[name] == Risk.UNKNOWN else 0.9
            if risks[name] == Risk.UNKNOWN:
                verdict.llm_error = "local LLM timed out"
            results.append((verdict, static))
        return results

    return fake_analysis


def _prepare_update(
    monkeypatch: pytest.MonkeyPatch,
    names: list[str],
    risks: dict[str, Risk],
    *,
    seen: list[str] | None = None,
) -> None:
    monkeypatch.setattr("yaysafe.cli.aur_targets", lambda invocation: names)
    monkeypatch.setattr("yaysafe.cli.yay_current_config", dict)
    monkeypatch.setattr("yaysafe.cli._retrieve_and_analyze", _analysis_with_risks(risks, seen))


def test_update_argument_classification() -> None:
    for args in (["-Syu"], ["-Syyu"], ["-Syu", "--devel"], ["-Sua"]):
        invocation = classify_args(args)
        assert invocation.install is True
        assert invocation.sysupgrade is True


def test_update_query_forwards_only_candidate_options() -> None:
    args = [
        "-Syu",
        "--devel",
        "--ignore",
        "ignored-package",
        "--aururl=https://aur.example.invalid",
        "--aurrpcurl",
        "https://rpc.example.invalid/rpc?",
        "--noconfirm",
        "--builddir",
        "/tmp/unrelated",
    ]
    assert update_query_options(args) == [
        "--devel",
        "--ignore",
        "ignored-package",
        "--aururl=https://aur.example.invalid",
        "--aurrpcurl",
        "https://rpc.example.invalid/rpc?",
    ]


def test_aur_update_discovery_uses_yay_and_preserves_devel(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: list[str] = []
    monkeypatch.setattr("yaysafe.yay.shutil.which", lambda command: "/usr/bin/yay")

    def fake_run(args, **kwargs):
        captured.extend(args)
        assert kwargs["stdin"] is subprocess.DEVNULL
        return subprocess.CompletedProcess(args, 0, "one-git\ntwo-bin\none-git\n", "")

    monkeypatch.setattr("yaysafe.yay.subprocess.run", fake_run)
    assert aur_upgrades(["-Syu", "--devel"]) == ["one-git", "two-bin"]
    assert captured == ["yay", "-Qua", "--quiet", "--color=never", "--devel"]


def test_aur_update_discovery_distinguishes_empty_from_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("yaysafe.yay.shutil.which", lambda command: "/usr/bin/yay")
    monkeypatch.setattr(
        "yaysafe.yay.subprocess.run",
        lambda args, **kwargs: subprocess.CompletedProcess(args, 1, "", ""),
    )
    assert aur_upgrades(["-Syu"]) == []

    monkeypatch.setattr(
        "yaysafe.yay.subprocess.run",
        lambda args, **kwargs: subprocess.CompletedProcess(
            args, 1, "", "error: failed to query the AUR"
        ),
    )
    with pytest.raises(YayError, match="failed to query the AUR"):
        aur_upgrades(["-Syu"])


def test_aur_update_discovery_rejects_unexpected_output(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("yaysafe.yay.shutil.which", lambda command: "/usr/bin/yay")
    monkeypatch.setattr(
        "yaysafe.yay.subprocess.run",
        lambda args, **kwargs: subprocess.CompletedProcess(args, 0, "package 1.0-1 -> 1.1-1\n", ""),
    )
    with pytest.raises(YayError, match="unexpected AUR update output"):
        aur_upgrades(["-Syu"])


def test_official_only_update_skips_security_scan_and_preserves_args(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original = ["-Syyu", "--noconfirm"]
    captured: list[list[str]] = []
    monkeypatch.setattr("yaysafe.cli.aur_targets", lambda invocation: [])
    monkeypatch.setattr(
        "yaysafe.cli._retrieve_and_analyze",
        lambda *args, **kwargs: pytest.fail("official updates must not be scanned"),
    )
    monkeypatch.setattr("yaysafe.cli.run_yay", lambda args, **kwargs: captured.append(args) or 7)
    output = StringIO()

    result = handle_yay(original, Config(), UI(UIConfig(color=False), out=output))

    assert result == 7
    assert captured == [original]
    assert "No AUR updates require security analysis." in output.getvalue()


@pytest.mark.parametrize("original", [["-Syu"], ["-Syu", "--devel"]])
def test_single_low_aur_update_is_scanned_before_yay(
    monkeypatch: pytest.MonkeyPatch, original: list[str]
) -> None:
    events: list[str] = []
    _prepare_update(monkeypatch, ["demo-git"], {"demo-git": Risk.LOW}, seen=events)

    def fake_run(args, **kwargs):
        events.append("yay")
        assert args[: len(original)] == original
        assert "--builddir" in args
        assert kwargs["env"] is not None
        return 0

    monkeypatch.setattr("yaysafe.cli.run_yay", fake_run)

    assert handle_yay(original, Config(), UI(UIConfig(color=False), out=StringIO())) == 0
    assert events == ["demo-git", "yay"]


def test_multiple_aur_updates_are_all_scanned_and_confirmed_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: list[str] = []
    names = ["package-a", "package-b", "package-c"]
    _prepare_update(
        monkeypatch,
        names,
        {"package-a": Risk.LOW, "package-b": Risk.LOW, "package-c": Risk.MEDIUM},
        seen=seen,
    )
    prompts: list[str] = []
    monkeypatch.setattr("builtins.input", lambda prompt="": prompts.append(prompt) or "y")
    invoked: list[list[str]] = []
    monkeypatch.setattr("yaysafe.cli.run_yay", lambda args, **kwargs: invoked.append(args) or 0)
    output = StringIO()

    assert handle_yay(["-Sua"], Config(), UI(UIConfig(color=False), out=output)) == 0
    assert seen == names
    assert len(prompts) == 1
    assert "Continue with the full update?" in prompts[0]
    assert len(invoked) == 1
    assert invoked[0][0] == "-Sua"
    assert "AUR update security summary" in output.getvalue()
    assert "3 AUR updates analyzed." in output.getvalue()


@pytest.mark.parametrize("args", [["-Syu"], ["-Syu", "--noconfirm"]])
def test_high_update_requires_explicit_yaysafe_confirmation(
    monkeypatch: pytest.MonkeyPatch, args: list[str]
) -> None:
    _prepare_update(monkeypatch, ["risky"], {"risky": Risk.HIGH})
    monkeypatch.setattr("builtins.input", lambda prompt="": "")
    monkeypatch.setattr(
        "yaysafe.cli.run_yay", lambda args, **kwargs: pytest.fail("yay must not run")
    )

    assert handle_yay(args, Config(), UI(UIConfig(color=False), out=StringIO())) == EXIT_BLOCKED


def test_critical_update_blocks_the_entire_transaction(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _prepare_update(
        monkeypatch,
        ["safe", "blocked"],
        {"safe": Risk.LOW, "blocked": Risk.CRITICAL},
    )
    monkeypatch.setattr(
        "builtins.input", lambda prompt="": pytest.fail("blocked updates are not prompted")
    )
    monkeypatch.setattr(
        "yaysafe.cli.run_yay", lambda args, **kwargs: pytest.fail("yay must not run")
    )

    assert handle_yay(["-Syu"], Config(), UI(UIConfig(color=False), out=StringIO())) == EXIT_BLOCKED


def test_unknown_llm_update_is_not_silently_allowed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _prepare_update(monkeypatch, ["unknown"], {"unknown": Risk.UNKNOWN})
    monkeypatch.setattr("builtins.input", lambda prompt="": "")
    monkeypatch.setattr(
        "yaysafe.cli.run_yay", lambda args, **kwargs: pytest.fail("yay must not run")
    )

    assert handle_yay(["-Syu"], Config(), UI(UIConfig(color=False), out=StringIO())) == EXIT_UNKNOWN


def test_retrieval_failure_becomes_unknown_and_defaults_to_abort(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("yaysafe.cli.aur_targets", lambda invocation: ["missing"])
    monkeypatch.setattr("yaysafe.cli.yay_current_config", dict)
    monkeypatch.setattr(
        "yaysafe.cli._retrieve_and_analyze",
        lambda *args, **kwargs: (_ for _ in ()).throw(AURError("AUR unavailable")),
    )
    monkeypatch.setattr("builtins.input", lambda prompt="": "")
    monkeypatch.setattr(
        "yaysafe.cli.run_yay", lambda args, **kwargs: pytest.fail("yay must not run")
    )
    output = StringIO()

    assert (
        handle_yay(
            ["-Syu"],
            Config(),
            UI(UIConfig(color=False), out=output, err=output),
        )
        == EXIT_UNKNOWN
    )
    assert "UNKNOWN" in output.getvalue()
    assert "AUR unavailable" in output.getvalue()


def test_update_discovery_failure_can_only_continue_by_explicit_override(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original = ["-Syu", "--noconfirm", "--devel"]
    monkeypatch.setattr(
        "yaysafe.cli.aur_targets",
        lambda invocation: (_ for _ in ()).throw(YayError("update query timed out")),
    )
    monkeypatch.setattr("builtins.input", lambda prompt="": "yes")
    invoked: list[list[str]] = []
    monkeypatch.setattr("yaysafe.cli.run_yay", lambda args, **kwargs: invoked.append(args) or 0)

    assert handle_yay(original, Config(), UI(UIConfig(color=False), out=StringIO())) == 0
    assert invoked == [original]


def test_reviewed_update_content_change_aborts_before_yay(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def changed_analysis(names, destination, config, ui, **kwargs):
        results = _analysis_with_risks({"changed": Risk.LOW})(
            names, destination, config, ui, **kwargs
        )
        (destination / "changed/PKGBUILD").write_text(
            "pkgname=changed\npkgver=3\npkgrel=1\n", encoding="utf-8"
        )
        return results

    monkeypatch.setattr("yaysafe.cli.aur_targets", lambda invocation: ["changed"])
    monkeypatch.setattr("yaysafe.cli.yay_current_config", dict)
    monkeypatch.setattr("yaysafe.cli._retrieve_and_analyze", changed_analysis)
    monkeypatch.setattr(
        "yaysafe.cli.run_yay", lambda args, **kwargs: pytest.fail("yay must not run")
    )

    with pytest.raises(ScanError, match="content changed after analysis"):
        handle_yay(["-Syu"], Config(), UI(UIConfig(color=False), out=StringIO()))


def test_update_analysis_cache_reuses_only_exact_content(tmp_path) -> None:
    repository = tmp_path / "cache-demo"
    repository.mkdir()
    pkgbuild = repository / "PKGBUILD"
    pkgbuild.write_text("pkgname=cache-demo\npkgver=1\npkgrel=1\n", encoding="utf-8")
    retrieved = RetrievedPackage(
        AURPackage("cache-demo", "cache-demo", "1-1"),
        repository,
        ["cache-demo"],
    )
    config = Config()
    cache = ScanCache(tmp_path / "cache")

    first, first_static = analyze_retrieved(retrieved, config, cache, use_llm=False, use_cache=True)
    second, second_static = analyze_retrieved(
        retrieved, config, cache, use_llm=False, use_cache=True
    )
    assert first.cached is False
    assert second.cached is True
    assert second_static.content_digest == first_static.content_digest

    pkgbuild.write_text("pkgname=cache-demo\npkgver=2\npkgrel=1\n", encoding="utf-8")
    changed, changed_static = analyze_retrieved(
        retrieved, config, cache, use_llm=False, use_cache=True
    )
    assert changed.cached is False
    assert changed_static.content_digest != first_static.content_digest
