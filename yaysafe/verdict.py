from __future__ import annotations

import dataclasses
import re
from enum import StrEnum

from yaysafe.config import PolicyConfig
from yaysafe.models import (
    RISK_ORDER,
    Assessment,
    Finding,
    LLMResult,
    Risk,
    StaticAssessment,
    StaticResult,
    Verdict,
)


class PolicyAction(StrEnum):
    ALLOW = "allow"
    CONFIRM = "confirm"
    BLOCK = "block"


def higher_risk(left: Risk, right: Risk) -> Risk:
    if left == Risk.UNKNOWN:
        return right
    if right == Risk.UNKNOWN:
        return left
    return max((left, right), key=RISK_ORDER.__getitem__)


def hard_rule_floor(findings: list[Finding]) -> Risk:
    floor = Risk.INFO
    for finding in findings:
        if not finding.hard:
            continue
        if finding.severity == Risk.CRITICAL:
            floor = higher_risk(floor, Risk.HIGH)
        elif finding.severity == Risk.HIGH:
            floor = higher_risk(floor, Risk.MEDIUM)
    return floor


def _normalized_evidence(value: str) -> str:
    return re.sub(r"[^a-z0-9$@/._+-]+", "", value.lower())


def _same_behavior(left: Finding, right: Finding) -> bool:
    if left.file != right.file or left.line != right.line:
        return False
    left_evidence = _normalized_evidence(left.matched_text)
    right_evidence = _normalized_evidence(right.matched_text)
    evidence_matches = bool(
        left_evidence
        and right_evidence
        and (
            left_evidence == right_evidence
            or left_evidence in right_evidence
            or right_evidence in left_evidence
        )
    )
    rule_matches = left.rule_id.removeprefix("llm-") == right.rule_id.removeprefix("llm-")
    category_fallback = left.category == right.category and (
        not left_evidence or not right_evidence
    )
    return evidence_matches or rule_matches or category_fallback


def merge_findings(
    static_findings: list[Finding],
    llm_findings: list[Finding],
    assessments: list[StaticAssessment],
) -> list[Finding]:
    assessment_map = {(item.rule_id, item.file, item.line): item for item in assessments}
    merged: list[Finding] = []
    for finding in static_findings:
        assessment = assessment_map.get((finding.rule_id, finding.file, finding.line))
        severity = finding.severity
        if assessment and not finding.hard:
            if assessment.assessment in {
                Assessment.CONTEXTUAL_BUT_LEGITIMATE,
                Assessment.FALSE_POSITIVE,
            }:
                severity = Risk.INFO
            elif assessment.assessment == Assessment.UNCERTAIN:
                severity = min((severity, Risk.MEDIUM), key=RISK_ORDER.__getitem__)
        merged.append(
            dataclasses.replace(
                finding,
                severity=severity,
                detected_by=("static",),
                assessment=assessment.assessment.value if assessment else "",
                assessment_reason=assessment.reason if assessment else "",
            )
        )

    for finding in llm_findings:
        candidate = dataclasses.replace(finding, detected_by=("llm",))
        duplicate = next((item for item in merged if _same_behavior(item, candidate)), None)
        if duplicate is None:
            merged.append(candidate)
            continue
        index = merged.index(duplicate)
        merged[index] = dataclasses.replace(
            duplicate,
            severity=higher_risk(duplicate.severity, candidate.severity),
            description=candidate.description or duplicate.description,
            matched_text=candidate.matched_text or duplicate.matched_text,
            hard=duplicate.hard or candidate.hard,
            detected_by=tuple(dict.fromkeys((*duplicate.detected_by, "llm"))),
        )
    return merged


def combine_results(
    package: str, static: StaticResult, llm: LLMResult | None, *, llm_requested: bool
) -> Verdict:
    static_risk = static.risk
    hard_findings = [finding for finding in static.findings if finding.hard]
    severe_hard_findings = [
        finding
        for finding in hard_findings
        if RISK_ORDER[finding.severity] >= RISK_ORDER[Risk.HIGH]
    ]
    floor = hard_rule_floor(hard_findings)
    if not llm_requested:
        final_risk = static_risk
        llm_risk = None
        summary = "Deterministic analysis completed; LLM analysis was disabled."
        confidence = None
    elif llm is None or llm.risk == Risk.UNKNOWN:
        llm_risk = Risk.UNKNOWN
        final_risk = (
            max(
                (finding.severity for finding in severe_hard_findings),
                key=RISK_ORDER.__getitem__,
            )
            if severe_hard_findings
            else Risk.UNKNOWN
        )
        summary = llm.summary if llm else "LLM analysis was unavailable; safety is unknown."
        confidence = None
    else:
        llm_risk = llm.risk
        final_risk = higher_risk(llm.risk, floor)
        summary = llm.summary
        confidence = llm.confidence
    disagreement = bool(llm and llm.risk != Risk.UNKNOWN and final_risk != llm.risk)
    assessments = [] if llm is None else llm.static_assessments
    llm_findings = [] if llm is None else llm.findings
    return Verdict(
        package=package,
        risk=final_risk,
        confidence=confidence,
        summary=summary,
        static_risk=static_risk,
        llm_risk=llm_risk,
        static_findings=static.findings,
        llm_findings=llm_findings,
        metadata=static.metadata,
        llm_model="" if llm is None else llm.model,
        llm_error="" if llm is None else llm.error,
        disagreement=disagreement,
        merged_findings=merge_findings(static.findings, llm_findings, assessments),
        static_assessments=assessments,
    )


def policy_action(risk: Risk, policy: PolicyConfig) -> PolicyAction:
    if risk == Risk.CRITICAL:
        return PolicyAction.BLOCK if policy.block_critical else PolicyAction.CONFIRM
    if risk == Risk.HIGH:
        return PolicyAction.CONFIRM if policy.confirm_high else PolicyAction.ALLOW
    if risk == Risk.MEDIUM:
        return PolicyAction.CONFIRM if policy.confirm_medium else PolicyAction.ALLOW
    if risk == Risk.UNKNOWN:
        return PolicyAction.BLOCK if policy.fail_closed else PolicyAction.CONFIRM
    if risk == Risk.LOW:
        return PolicyAction.ALLOW if policy.allow_low else PolicyAction.CONFIRM
    return PolicyAction.ALLOW if policy.allow_info else PolicyAction.CONFIRM
