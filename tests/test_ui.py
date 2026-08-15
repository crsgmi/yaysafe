from __future__ import annotations

from io import StringIO

from yaysafe.config import UIConfig
from yaysafe.models import Assessment, Finding, PackageMetadata, Risk, StaticAssessment, Verdict
from yaysafe.ui import UI


def _verdict(finding: Finding) -> Verdict:
    finding = Finding.from_dict({**finding.to_dict(), "detected_by": ["llm"]})
    return Verdict(
        package="example",
        risk=Risk.LOW,
        confidence=0.9,
        summary="No suspicious activities detected.",
        static_risk=Risk.INFO,
        llm_risk=Risk.LOW,
        static_findings=[],
        llm_findings=[finding],
        metadata=PackageMetadata(name="example"),
        merged_findings=[finding],
    )


def test_benign_llm_observation_is_a_security_note() -> None:
    output = StringIO()
    finding = Finding(Risk.INFO, "llm-source", "PKGBUILD", 1, "source=...", "Uses GitHub")
    UI(UIConfig(color=False), out=output).verdict(_verdict(finding))
    shown = output.getvalue()
    assert ":: Security notes" in shown
    assert "INFO" in shown
    assert "suspicious" not in shown


def test_medium_llm_finding_uses_security_findings_heading() -> None:
    output = StringIO()
    finding = Finding(Risk.MEDIUM, "llm-network", "PKGBUILD", 2, "curl ...", "Downloads")
    UI(UIConfig(color=False), out=output).verdict(_verdict(finding))
    shown = output.getvalue()
    assert ":: Security findings" in shown
    assert "MEDIUM" in shown


def test_empty_verdict_is_concise() -> None:
    output = StringIO()
    verdict = _verdict(Finding(Risk.INFO, "skipped-checksum", "PKGBUILD", 1, "SKIP", "VCS"))
    verdict.merged_findings[0] = Finding.from_dict(
        {**verdict.merged_findings[0].to_dict(), "detected_by": ["static"]}
    )
    UI(UIConfig(color=False), out=output).verdict(verdict)
    shown = output.getvalue()
    assert "No significant security concerns detected" in shown
    assert "Static findings" not in shown


def test_unknown_verdict_shows_llm_failure() -> None:
    output = StringIO()
    verdict = Verdict(
        package="example",
        risk=Risk.UNKNOWN,
        confidence=None,
        summary="Unavailable",
        static_risk=Risk.INFO,
        llm_risk=Risk.UNKNOWN,
        static_findings=[],
        llm_findings=[],
        metadata=PackageMetadata(name="example"),
        llm_error="connection timed out",
    )
    UI(UIConfig(color=False), out=output).verdict(verdict)
    shown = output.getvalue()
    assert ":: LLM analysis failed" in shown
    assert "connection timed out" in shown
    assert "Package safety could not be determined" in shown


def test_hard_finding_does_not_hide_llm_failure() -> None:
    output = StringIO()
    finding = Finding(
        Risk.HIGH,
        "hard-rule",
        "PKGBUILD",
        4,
        "danger",
        "Dangerous behavior.",
        hard=True,
        detected_by=("static",),
    )
    verdict = Verdict(
        package="example",
        risk=Risk.HIGH,
        confidence=None,
        summary="LLM unavailable",
        static_risk=Risk.HIGH,
        llm_risk=Risk.UNKNOWN,
        static_findings=[finding],
        llm_findings=[],
        metadata=PackageMetadata(name="example"),
        llm_error="connection timed out",
        merged_findings=[finding],
    )
    UI(UIConfig(color=False), out=output).verdict(verdict)
    shown = output.getvalue()
    assert ":: LLM analysis failed" in shown
    assert "connection timed out" in shown
    assert ":: Security findings" in shown


def test_detailed_view_includes_standalone_llm_findings() -> None:
    output = StringIO()
    finding = Finding(
        Risk.MEDIUM,
        "llm-telemetry",
        "PKGBUILD",
        8,
        "curl telemetry.invalid",
        "Sends unexpected telemetry.",
        "telemetry",
        detected_by=("llm",),
    )
    verdict = _verdict(finding)
    UI(UIConfig(color=False), out=output).verdict(verdict, verbose=True)
    shown = output.getvalue()
    assert "LLM finding:" in shown
    assert "Sends unexpected telemetry" in shown


def test_detailed_view_connects_static_rule_to_llm_assessment() -> None:
    output = StringIO()
    static = Finding(
        Risk.HIGH,
        "setuid",
        "PKGBUILD",
        52,
        'chmod 4755 "$pkgdir/opt/browser/chrome-sandbox"',
        "Stages a SUID helper.",
    )
    assessment = StaticAssessment(
        "setuid",
        "PKGBUILD",
        52,
        Assessment.CONTEXTUAL_BUT_LEGITIMATE,
        "Normal browser sandbox packaging.",
    )
    merged = Finding.from_dict(
        {
            **static.to_dict(),
            "severity": "info",
            "assessment": assessment.assessment.value,
            "assessment_reason": assessment.reason,
            "detected_by": ["static"],
        }
    )
    verdict = Verdict(
        package="browser",
        risk=Risk.LOW,
        confidence=0.95,
        summary="Normal browser packaging.",
        static_risk=Risk.HIGH,
        llm_risk=Risk.LOW,
        static_findings=[static],
        llm_findings=[],
        metadata=PackageMetadata(name="browser"),
        merged_findings=[merged],
        static_assessments=[assessment],
    )
    UI(UIConfig(color=False), out=output).verdict(verdict, verbose=True)
    shown = output.getvalue()
    assert ":: Analysis details" in shown
    assert "contextual_but_legitimate" in shown
    assert "Normal browser sandbox packaging" in shown
    assert "Final impact:" in shown
    assert "INFO" in shown
