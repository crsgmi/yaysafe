from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any


class Risk(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    UNKNOWN = "unknown"


class Assessment(StrEnum):
    CONFIRMED_RISK = "confirmed_risk"
    CONTEXTUAL_BUT_LEGITIMATE = "contextual_but_legitimate"
    FALSE_POSITIVE = "false_positive"
    UNCERTAIN = "uncertain"


RISK_ORDER: dict[Risk, int] = {
    Risk.INFO: 0,
    Risk.LOW: 1,
    Risk.MEDIUM: 2,
    Risk.HIGH: 3,
    Risk.CRITICAL: 4,
    Risk.UNKNOWN: -1,
}


@dataclass(frozen=True, slots=True)
class Finding:
    severity: Risk
    rule_id: str
    file: str
    line: int
    matched_text: str
    description: str
    category: str = "static-analysis"
    hard: bool = False
    detected_by: tuple[str, ...] = ()
    assessment: str = ""
    assessment_reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["severity"] = self.severity.value
        return result

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Finding:
        return cls(
            severity=Risk(str(data["severity"]).lower()),
            rule_id=str(data.get("rule_id", "llm")),
            file=str(data.get("file", "")),
            line=int(data.get("line", 0)),
            matched_text=str(data.get("matched_text", data.get("evidence", ""))),
            description=str(data.get("description", "")),
            category=str(data.get("category", "static-analysis")),
            hard=bool(data.get("hard", False)),
            detected_by=tuple(str(value) for value in data.get("detected_by", ())),
            assessment=str(data.get("assessment", "")),
            assessment_reason=str(data.get("assessment_reason", "")),
        )


@dataclass(frozen=True, slots=True)
class StaticAssessment:
    rule_id: str
    file: str
    line: int
    assessment: Assessment
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "file": self.file,
            "line": self.line,
            "assessment": self.assessment.value,
            "reason": self.reason,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> StaticAssessment:
        return cls(
            rule_id=str(data["rule_id"]),
            file=str(data["file"]),
            line=int(data["line"]),
            assessment=Assessment(str(data["assessment"])),
            reason=str(data["reason"]),
        )


@dataclass(slots=True)
class PackageMetadata:
    name: str
    package_base: str = ""
    description: str = ""
    url: str = ""
    version: str = ""
    source_urls: list[str] = field(default_factory=list)
    source_domains: list[str] = field(default_factory=list)
    skipped_checksums: list[str] = field(default_factory=list)
    vcs_package: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class InspectedFile:
    relative_path: str
    content: str
    size: int
    path: Path = field(compare=False, repr=False)


@dataclass(slots=True)
class StaticResult:
    findings: list[Finding]
    metadata: PackageMetadata
    files: list[InspectedFile]
    content_digest: str
    skipped_files: list[str] = field(default_factory=list)

    @property
    def risk(self) -> Risk:
        if not self.findings:
            return Risk.INFO
        return max((finding.severity for finding in self.findings), key=RISK_ORDER.__getitem__)


@dataclass(slots=True)
class LLMResult:
    risk: Risk
    safe: bool
    confidence: float | None
    summary: str
    findings: list[Finding] = field(default_factory=list)
    static_assessments: list[StaticAssessment] = field(default_factory=list)
    model: str = ""
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "risk": self.risk.value,
            "safe": self.safe,
            "confidence": self.confidence,
            "summary": self.summary,
            "findings": [finding.to_dict() for finding in self.findings],
            "static_assessments": [item.to_dict() for item in self.static_assessments],
            "model": self.model,
            "error": self.error,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> LLMResult:
        return cls(
            risk=Risk(str(data["risk"]).lower()),
            safe=bool(data.get("safe", False)),
            confidence=(float(data["confidence"]) if data.get("confidence") is not None else None),
            summary=str(data.get("summary", "")),
            findings=[Finding.from_dict(item) for item in data.get("findings", [])],
            static_assessments=[
                StaticAssessment.from_dict(item) for item in data.get("static_assessments", [])
            ],
            model=str(data.get("model", "")),
            error=str(data.get("error", "")),
        )


@dataclass(slots=True)
class Verdict:
    package: str
    risk: Risk
    confidence: float | None
    summary: str
    static_risk: Risk
    llm_risk: Risk | None
    static_findings: list[Finding]
    llm_findings: list[Finding]
    metadata: PackageMetadata
    llm_model: str = ""
    llm_error: str = ""
    disagreement: bool = False
    cached: bool = False
    merged_findings: list[Finding] = field(default_factory=list)
    static_assessments: list[StaticAssessment] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "package": self.package,
            "risk": self.risk.value,
            "confidence": self.confidence,
            "summary": self.summary,
            "static_risk": self.static_risk.value,
            "llm_risk": self.llm_risk.value if self.llm_risk else None,
            "static_findings": [finding.to_dict() for finding in self.static_findings],
            "llm_findings": [finding.to_dict() for finding in self.llm_findings],
            "metadata": self.metadata.to_dict(),
            "llm_model": self.llm_model,
            "llm_error": self.llm_error,
            "disagreement": self.disagreement,
            "cached": self.cached,
            "merged_findings": [finding.to_dict() for finding in self.merged_findings],
            "static_assessments": [item.to_dict() for item in self.static_assessments],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Verdict:
        metadata = PackageMetadata(**data.get("metadata", {"name": str(data["package"])}))
        return cls(
            package=str(data["package"]),
            risk=Risk(str(data["risk"])),
            confidence=(float(data["confidence"]) if data.get("confidence") is not None else None),
            summary=str(data.get("summary", "")),
            static_risk=Risk(str(data.get("static_risk", "info"))),
            llm_risk=Risk(str(data["llm_risk"])) if data.get("llm_risk") else None,
            static_findings=[Finding.from_dict(x) for x in data.get("static_findings", [])],
            llm_findings=[Finding.from_dict(x) for x in data.get("llm_findings", [])],
            metadata=metadata,
            llm_model=str(data.get("llm_model", "")),
            llm_error=str(data.get("llm_error", "")),
            disagreement=bool(data.get("disagreement", False)),
            cached=bool(data.get("cached", False)),
            merged_findings=[Finding.from_dict(x) for x in data.get("merged_findings", [])],
            static_assessments=[
                StaticAssessment.from_dict(item) for item in data.get("static_assessments", [])
            ],
        )
