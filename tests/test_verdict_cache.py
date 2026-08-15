from __future__ import annotations

import json
from pathlib import Path

from yaysafe.cache import ScanCache
from yaysafe.cli import _profile
from yaysafe.config import Config, LLMConfig, PolicyConfig, ScannerConfig
from yaysafe.models import (
    Assessment,
    Finding,
    LLMResult,
    PackageMetadata,
    Risk,
    StaticAssessment,
    StaticResult,
)
from yaysafe.scanner import scan_repository
from yaysafe.verdict import PolicyAction, combine_results, higher_risk, policy_action

FIXTURES = Path(__file__).parent / "fixtures"


def test_risk_ordering() -> None:
    assert higher_risk(Risk.LOW, Risk.HIGH) == Risk.HIGH
    assert higher_risk(Risk.CRITICAL, Risk.MEDIUM) == Risk.CRITICAL


def test_hard_high_finding_sets_medium_floor_for_known_llm_verdict() -> None:
    static = scan_repository(FIXTURES / "suspicious-package", "suspicious-package", ScannerConfig())
    llm = LLMResult(Risk.LOW, True, 0.99, "Looks safe")
    verdict = combine_results("suspicious-package", static, llm, llm_requested=True)
    assert verdict.risk == Risk.MEDIUM
    assert verdict.disagreement is True


def test_contextual_high_finding_can_be_downgraded_by_llm() -> None:
    finding = Finding(
        Risk.HIGH,
        "setuid",
        "PKGBUILD",
        52,
        'chmod 4755 "$pkgdir/opt/browser/chrome-sandbox"',
        "Stages a SUID helper.",
        "privilege-escalation",
    )
    static = StaticResult([finding], PackageMetadata(name="browser"), [], "digest")
    assessment = StaticAssessment(
        "setuid",
        "PKGBUILD",
        52,
        Assessment.CONTEXTUAL_BUT_LEGITIMATE,
        "The browser sandbox helper is staged beneath $pkgdir.",
    )
    llm = LLMResult(Risk.LOW, True, 0.95, "Normal browser packaging", [], [assessment])
    verdict = combine_results("browser", static, llm, llm_requested=True)
    assert verdict.risk == Risk.LOW
    assert verdict.disagreement is False
    assert verdict.merged_findings[0].severity == Risk.INFO


def test_unknown_with_hard_finding_uses_static_hard_risk() -> None:
    static = scan_repository(FIXTURES / "suspicious-package", "suspicious-package", ScannerConfig())
    llm = LLMResult(Risk.UNKNOWN, False, None, "Unavailable")
    verdict = combine_results("suspicious-package", static, llm, llm_requested=True)
    assert verdict.risk == Risk.HIGH


def test_duplicate_static_and_llm_finding_is_merged() -> None:
    static_finding = Finding(
        Risk.HIGH,
        "setuid",
        "PKGBUILD",
        52,
        'chmod 4755 "$pkgdir/opt/browser/chrome-sandbox"',
        "Stages a SUID helper.",
        "privilege-escalation",
    )
    llm_finding = Finding(
        Risk.MEDIUM,
        "llm-privilege-escalation",
        "PKGBUILD",
        52,
        'chmod 4755 "$pkgdir/opt/browser/chrome-sandbox"',
        "Installs a SUID browser helper.",
        "privilege-escalation",
    )
    static = StaticResult([static_finding], PackageMetadata(name="browser"), [], "digest")
    llm = LLMResult(Risk.MEDIUM, False, 0.9, "Review SUID helper", [llm_finding])
    verdict = combine_results("browser", static, llm, llm_requested=True)
    assert len(verdict.merged_findings) == 1
    assert verdict.merged_findings[0].detected_by == ("static", "llm")


def test_distinct_findings_on_same_line_and_category_are_not_merged() -> None:
    static_finding = Finding(
        Risk.MEDIUM,
        "first-action",
        "PKGBUILD",
        10,
        "chmod 777 first",
        "Makes one file writable.",
        "permissions",
    )
    llm_finding = Finding(
        Risk.MEDIUM,
        "llm-permissions",
        "PKGBUILD",
        10,
        "setfacl -m u:other:rwx second",
        "Changes a different file ACL.",
        "permissions",
    )
    static = StaticResult([static_finding], PackageMetadata(name="example"), [], "digest")
    llm = LLMResult(Risk.MEDIUM, False, 0.9, "Review permissions", [llm_finding])
    verdict = combine_results("example", static, llm, llm_requested=True)
    assert len(verdict.merged_findings) == 2


def test_unknown_is_not_safe() -> None:
    static = scan_repository(FIXTURES / "safe-package", "safe-package", ScannerConfig())
    llm = LLMResult(Risk.UNKNOWN, False, None, "Unavailable")
    verdict = combine_results("safe-package", static, llm, llm_requested=True)
    assert verdict.risk == Risk.UNKNOWN
    assert policy_action(verdict.risk, PolicyConfig()) == PolicyAction.CONFIRM
    assert policy_action(verdict.risk, PolicyConfig(fail_closed=True)) == PolicyAction.BLOCK


def test_cache_round_trip_and_profile_key(tmp_path: Path) -> None:
    static = scan_repository(FIXTURES / "safe-package", "safe-package", ScannerConfig())
    verdict = combine_results("safe-package", static, None, llm_requested=False)
    cache = ScanCache(tmp_path)
    key1 = cache.key(static.content_digest, {"llm": False})
    key2 = cache.key(static.content_digest, {"llm": True})
    assert key1 != key2
    cache.store(key1, static.content_digest, verdict)
    loaded = cache.load(key1, static.content_digest)
    assert loaded is not None and loaded.cached is True
    assert loaded.risk == verdict.risk


def test_cache_profile_distinguishes_llm_providers() -> None:
    static = scan_repository(FIXTURES / "safe-package", "safe-package", ScannerConfig())
    lm_studio = Config(llm=LLMConfig(provider="lmstudio", model="same-model"))
    ollama = Config(llm=LLMConfig(provider="ollama", model="same-model"))
    first = _profile(lm_studio, static, llm_requested=True, model="same-model")
    second = _profile(ollama, static, llm_requested=True, model="same-model")
    assert first["provider"] == "lmstudio"
    assert second["provider"] == "ollama"
    assert ScanCache.key(static.content_digest, first) != ScanCache.key(
        static.content_digest, second
    )


def test_corrupt_cache_is_ignored(tmp_path: Path) -> None:
    cache = ScanCache(tmp_path)
    directory = tmp_path / "scans"
    directory.mkdir()
    (directory / "bad.json").write_text("broken")
    assert cache.load("bad", "expected-digest") is None


def test_cache_is_ignored_when_its_stored_digest_does_not_match(tmp_path: Path) -> None:
    static = scan_repository(FIXTURES / "safe-package", "safe-package", ScannerConfig())
    verdict = combine_results("safe-package", static, None, llm_requested=False)
    cache = ScanCache(tmp_path)
    key = cache.key(static.content_digest, {"llm": False})

    cache.store(key, "different-digest", verdict)

    assert cache.load(key, static.content_digest) is None


def test_cache_does_not_follow_symlink_entries(tmp_path: Path) -> None:
    cache = ScanCache(tmp_path)
    directory = tmp_path / "scans"
    directory.mkdir()
    outside = tmp_path / "outside.json"
    outside.write_text("{}")
    (directory / "linked.json").symlink_to(outside)
    assert cache.load("linked", "digest") is None


def test_expired_cache_entry_is_ignored(tmp_path: Path) -> None:
    static = scan_repository(FIXTURES / "safe-package", "safe-package", ScannerConfig())
    verdict = combine_results("safe-package", static, None, llm_requested=False)
    cache = ScanCache(tmp_path)
    key = cache.key(static.content_digest, {"llm": False})
    cache.store(key, static.content_digest, verdict)
    path = tmp_path / "scans" / f"{key}.json"
    payload = json.loads(path.read_text())
    payload["created_at"] = 0
    path.write_text(json.dumps(payload))
    assert cache.load(key, static.content_digest) is None
